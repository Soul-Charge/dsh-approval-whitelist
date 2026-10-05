// SPDX-License-Identifier: MIT
// The settings surface: the namespace schema, the two-layer fold, and the rule
// that a model chosen in Settings reaches the reviewer WITHOUT a restart.
import { assert, assertEqual, summary, test } from './harness.mjs'
import { SETTINGS_NAMESPACE, buildSettingsSchema, installSettings, settingsEntry } from '../src/settings.js'

console.log('== settings namespace ==')
await test('the namespace is a lowercase hyphenated identifier', () => {
  assertEqual(SETTINGS_NAMESPACE, 'approval-whitelist')
  assert(/^[a-z][a-z0-9-]*$/.test(SETTINGS_NAMESPACE), 'must match the settings namespace pattern')
})
await test('the schema carries no level/scope escape hatch', () => {
  // A model could otherwise be used to widen its own authority.
  const schema = buildSettingsSchema()
  const json = schema.toJSON()
  const keys = Object.keys(json.properties.aiReview.properties)
  assert(keys.indexOf('level') < 0, 'level must not be configurable')
  assert(keys.indexOf('scope') < 0, 'scope must not be configurable')
  assert(keys.indexOf('provider') >= 0 && keys.indexOf('model') >= 0, 'provider/model must be configurable')
})
await test('the fold drops unknown keys and coerces bad types', () => {
  const schema = buildSettingsSchema()
  const folded = schema({ aiReview: {
    enabled: 'yes', provider: 'p', model: 'm', reasoningEffort: 7,
    tools: ['bash'], maxSessionRules: 'lots', minScopeDepth: null,
    // These must never survive: the rule level/scope are not configurable.
    level: 'data', scope: 'global',
  } })
  assertEqual(folded.aiReview.enabled, false, 'a non-boolean switch falls back to off')
  assertEqual(folded.aiReview.reasoningEffort, 'low', 'a non-string falls back to the reviewer default')
  assertEqual(folded.aiReview.maxSessionRules, 3, 'a non-number falls back')
  assertEqual(folded.aiReview.minScopeDepth, 3)
  assertEqual(folded.aiReview.tools, ['bash'])
  assertEqual(folded.aiReview.level, undefined, 'level must be dropped by the fold')
  assertEqual(folded.aiReview.scope, undefined, 'scope must be dropped by the fold')
})
await test('the schema folds defaults over an empty layer', () => {
  const schema = buildSettingsSchema()
  assertEqual(schema(undefined), { aiReview: Object.assign({}, {
    enabled: false, provider: '', model: '', reasoningEffort: 'low',
    timeoutMs: 8000, maxTokens: 16384, temperature: 0,
    maxSessionRules: 3, minScopeDepth: 3, tools: ['bash', 'pwsh'], ownPaths: [],
  }) })
})
await test('ownPaths defaults empty and accepts a list of strings', () => {
  const schema = buildSettingsSchema()
  // Deployment-specific working locations live in settings, never in the source.
  assertEqual(schema(undefined).aiReview.ownPaths, [], 'empty is the default')
  assertEqual(schema({ aiReview: { ownPaths: ['/srv/app', '~/extra'] } }).aiReview.ownPaths,
    ['/srv/app', '~/extra'], 'a string list is preserved')
  assertEqual(schema({ aiReview: { ownPaths: ['/ok', 7, ''] } }).aiReview.ownPaths,
    ['/ok'], 'non-strings are dropped')
  assertEqual(schema({ aiReview: { ownPaths: 'nope' } }).aiReview.ownPaths, [],
    'a wrong type falls back to empty, not to the tools list')
})
await test('the entry keeps the composition aiReview and defaults the rest', () => {
  const entry = settingsEntry({ aiReview: { enabled: true, provider: 'p', model: 'm' } })
  assertEqual(entry.aiReview.enabled, true)
  assertEqual(entry.aiReview.provider, 'p')
  assertEqual(entry.aiReview.model, 'm')
  assertEqual(entry.aiReview.maxSessionRules, 3, 'unset fields take the documented default')
  assert(Array.isArray(entry.aiReview.tools) && entry.aiReview.tools.length > 0)
  const empty = settingsEntry(undefined)
  assertEqual(empty.aiReview.enabled, false, 'no config means the layer stays off')
})
await test('an entry without tools falls back to the default tool list', () => {
  const entry = settingsEntry({ aiReview: { enabled: true, tools: [] } })
  assertEqual(entry.aiReview.tools, ['bash', 'pwsh'])
})

console.log('== installSettings: falls back without a settings service ==')
await test('no inject function means the composition entry is the value', () => {
  const entry = settingsEntry({ aiReview: { enabled: true, provider: 'x', model: 'y' } })
  const read = installSettings({}, entry, () => {})
  assertEqual(read().aiReview.provider, 'x')
})
await test('a context without the settings service keeps the entry', () => {
  let called = false
  const ctx = { inject: (names, cb) => { called = true; cb({}) } }
  const entry = settingsEntry({ aiReview: { enabled: true, provider: 'x', model: 'y' } })
  const read = installSettings(ctx, entry, () => {})
  assertEqual(called, true, 'the optional injection must be attempted')
  assertEqual(read().aiReview.provider, 'x', 'and the entry must survive its absence')
})
await test('a registered scope is read on every call (live settings)', async () => {
  let live = settingsEntry({ aiReview: { enabled: true, provider: 'first', model: 'm1' } })
  const ctx = {
    inject: (names, cb) => cb({
      settings: {
        register: () => ({
          get: () => live,
          watch: () => () => {},
          update: async () => {},
          replace: async () => {},
        }),
      },
    }),
    effect: () => () => {},
  }
  const entry = settingsEntry({ aiReview: { enabled: true, provider: 'base', model: 'm0' } })
  const read = installSettings(ctx, entry, () => {})
  assertEqual(read().aiReview.provider, 'first', 'the registered value wins')
  live = settingsEntry({ aiReview: { enabled: true, provider: 'second', model: 'm2' } })
  assertEqual(read().aiReview.provider, 'second', 'a later value is picked up without reinstalling')
})
await test('installSection receives every hook it calls', () => {
  // installSection calls setSource() AND onChange() (and again on unload).
  // Passing only setSource aborts the mount with 'hooks.onChange is not a function'.
  let captured = null
  const ctx = {
    inject: (names, cb) => cb({ settings: { installSection: (owner, ns, schema, subject, hooks) => { captured = hooks } } }),
    effect: () => () => {},
  }
  installSettings(ctx, settingsEntry({ aiReview: { enabled: true } }), () => {})
  assert(captured !== null, 'installSection must be called')
  assert(typeof captured.setSource === 'function', 'setSource is required')
  assert(typeof captured.onChange === 'function', 'onChange is required or the mount throws')
  captured.setSource(() => settingsEntry({ aiReview: { enabled: false } }))
  captured.onChange()
})
await test('a throwing settings service is reported, not fatal', async () => {
  const seen = []
  const ctx = {
    inject: (names, cb) => cb({ settings: { register: () => { throw new Error('nope') } } }),
    effect: () => () => {},
  }
  const entry = settingsEntry({ aiReview: { enabled: true, provider: 'x', model: 'y' } })
  const read = installSettings(ctx, entry, (op, target, error) => seen.push([op, target, String(error.message)]))
  assertEqual(read().aiReview.provider, 'x', 'the entry still answers')
  assertEqual(seen.length, 1, 'the failure must be reported once')
  assert(String(seen[0][2]).indexOf('nope') >= 0)
})

summary('settings')
