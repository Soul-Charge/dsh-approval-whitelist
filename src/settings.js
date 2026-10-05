// SPDX-License-Identifier: MIT
// Settings integration for the AI approval layer.
//
// The plugin owns one DSH settings namespace ("approval-whitelist") so the AI
// reviewer can be configured from Settings instead of by editing
// cordis.patch.yml. Two layers coexist, in this order of precedence:
//
//   1. the composition entry (cordis.patch.yml) - the base layer;
//   2. the user layer written through the settings surface.
//
// Reading goes through ctx.settings.register(), whose resolved value folds the
// two. A profile without dsh-settings still mounts this plugin: everything here
// is behind an optional injection, and the resolver falls back to the
// composition entry when no settings service is present.
import { DEFAULT_AI_CONFIG, DEFAULT_OWN_PATHS } from './ai.js'

/** The namespace shown in Settings. Lowercase, hyphenated, plugin-owned. */
export const SETTINGS_NAMESPACE = 'approval-whitelist'

// The settings service calls the registered schema directly (`schema(value)`)
// and asks it for `.toJSON()` when it describes namespaces. schemastery is one
// implementation of that contract, but this plugin does not depend on it: the
// namespace is small and fully owned here, so a self-contained schema keeps the
// plugin loadable in every profile (the engine links only profiles/node_modules
// while schemastery lives in profiles/web/node_modules).

/** The AI fields the namespace accepts, with their defaults. */
const AI_FIELD_SPEC = [
  ['enabled', 'boolean', DEFAULT_AI_CONFIG.enabled],
  ['provider', 'string', ''],
  ['model', 'string', ''],
  ['reasoningEffort', 'string', DEFAULT_AI_CONFIG.reasoningEffort],
  ['timeoutMs', 'number', DEFAULT_AI_CONFIG.timeoutMs],
  ['maxTokens', 'number', DEFAULT_AI_CONFIG.maxTokens],
  ['temperature', 'number', DEFAULT_AI_CONFIG.temperature],
  ['maxSessionRules', 'number', DEFAULT_AI_CONFIG.maxSessionRules],
  ['minScopeDepth', 'number', DEFAULT_AI_CONFIG.minScopeDepth],
]

function coerce(kind, value, fallback) {
  if (kind === 'boolean') return typeof value === 'boolean' ? value : fallback
  if (kind === 'number') return typeof value === 'number' && Number.isFinite(value) ? value : fallback
  return typeof value === 'string' ? value : fallback
}

function coerceTools(value) {
  if (!Array.isArray(value)) return DEFAULT_AI_CONFIG.tools.slice()
  const tools = value.filter((entry) => typeof entry === 'string' && entry !== '')
  return tools.length > 0 ? tools : DEFAULT_AI_CONFIG.tools.slice()
}

/** Extra operator working locations. Unlike tools, an empty list is meaningful. */
function coerceOwnPaths(value) {
  if (!Array.isArray(value)) return DEFAULT_OWN_PATHS.slice()
  return value.filter((entry) => typeof entry === 'string' && entry !== '')
}

/**
 * Build the namespace schema. Deliberately narrow: it exposes exactly what a
 * settings page may change about the AI layer. level and scope are NOT here -
 * an AI-created rule is always code/session, and no surface may configure that.
 *
 * The returned value is callable (`schema(value)` folds defaults over a merged
 * layer) and carries `toJSON()` for the settings descriptor. Unknown keys and
 * uncoercible values fall back to defaults, so a hand-edited settings.yaml can
 * never inject a rule level or a non-boolean switch.
 */
export function buildSettingsSchema() {
  const shape = {
    type: 'object',
    properties: {
      aiReview: {
        type: 'object',
        properties: Object.assign(
          {
            tools: { type: 'array', items: { type: 'string' }, default: DEFAULT_AI_CONFIG.tools.slice() },
            ownPaths: { type: 'array', items: { type: 'string' }, default: DEFAULT_OWN_PATHS.slice() },
          },
          AI_FIELD_SPEC.reduce((acc, entry) => {
            acc[entry[0]] = { type: entry[1], default: entry[2] }
            return acc
          }, {}),
        ),
      },
    },
  }
  const schema = (input) => {
    const source = input !== null && typeof input === 'object' ? input : {}
    const raw = source.aiReview !== null && typeof source.aiReview === 'object' ? source.aiReview : {}
    const aiReview = {}
    // Unknown keys are dropped here: they must not survive the fold.
    for (const entry of AI_FIELD_SPEC) aiReview[entry[0]] = coerce(entry[1], raw[entry[0]], entry[2])
    aiReview.tools = coerceTools(raw.tools)
    aiReview.ownPaths = coerceOwnPaths(raw.ownPaths)
    return { aiReview: aiReview }
  }
  schema.toJSON = () => shape
  return schema
}

/** The composition entry shaped for the schema (the base layer). */
export function settingsEntry(config) {
  const input = config !== null && typeof config === 'object' ? config : {}
  const ai = input.aiReview !== null && typeof input.aiReview === 'object' ? input.aiReview : {}
  return {
    aiReview: Object.assign({}, DEFAULT_AI_CONFIG, ai, {
      tools: Array.isArray(ai.tools) && ai.tools.length > 0 ? ai.tools.slice() : DEFAULT_AI_CONFIG.tools.slice(),
    }),
  }
}

/**
 * Install the settings namespace and hand back a live reader.
 *
 * @param ctx - plugin context.
 * @param entry - the composition entry (base + fallback value).
 * @param onError - reporter for a surface that cannot be wired.
 * @returns a function returning the resolved settings object.
 */
export function installSettings(ctx, entry, onError) {
  let source = () => entry
  if (typeof ctx.inject !== 'function') return () => source()
  ctx.inject(['settings'], (settingsCtx) => {
    const settings = settingsCtx !== null && typeof settingsCtx === 'object'
      ? (settingsCtx.settings !== undefined ? settingsCtx.settings : (typeof settingsCtx.get === 'function' ? settingsCtx.get('settings') : undefined))
      : undefined
    if (settings === undefined || settings === null) return
    const schema = buildSettingsSchema()
    try {
      // installSection is the current API; register is the older shape. Both
      // resolve the same two layers, so either one is correct here.
      if (typeof settings.installSection === 'function') {
        // installSection REQUIRES both hooks: it calls setSource(), onChange()
        // and (on unload) setSource()+onChange() again. Omitting onChange throws
        // 'hooks.onChange is not a function' and aborts the mount.
        settings.installSection(ctx, SETTINGS_NAMESPACE, schema, entry, {
          setSource: (current) => { source = current },
          onChange: () => {},
        })
        return
      }
      if (typeof settings.register === 'function') {
        const scope = settings.register(SETTINGS_NAMESPACE, schema, { base: entry })
        source = () => scope.get()
        if (typeof ctx.effect === 'function') ctx.effect(() => () => { source = () => entry })
      }
    } catch (error) {
      if (typeof onError === 'function') onError('install settings namespace', SETTINGS_NAMESPACE, error)
    }
  })
  return () => source()
}
