// SPDX-License-Identifier: MIT
// Rule model and the whitelist decision.
//
// Levels (taskbook section 4):
//   code - strictest, default. Only statically provable pure writes: the write/
//          edit tools' own target, and shell redirections / cp-like destinations
//          / ee -i / dd of=. Executing a program is never allowed.
//   data - explicit opt-in, higher risk. Everything code allows, plus running
//          programs whose operand paths all stay inside the rule root or the
//          session workspace. The program's own behaviour is NOT provable; the
//          user accepts that by declaring the rule as data.
// Red lines identical at both levels: no deletion, no opaque syntax, no device
// namespaces, no paths outside the rule root, no symlinked target.
import os from 'node:os'
import { deviceNamespace, hasSymlinkComponent, isFilesystemRoot, isWithin, normalizePath } from './paths.js'
import { analyzeCommand, embeddedPaths } from './targets.js'
import { guardReason } from './guard.js'

export const DEFAULT_TOOLS = ['write', 'edit', 'apply_patch', 'str_replace_editor', 'bash', 'pwsh']
const FILE_TOOLS = new Set(['write', 'edit', 'apply_patch', 'str_replace_editor'])
const SHELL_TOOLS = new Set(['bash', 'pwsh'])

export const DEFAULT_CONFIG = {
  enabled: true,
  storePath: '~/.dsh/approval-whitelist.json',
  auditPath: '~/.dsh/approval-whitelist.audit.log',
  audit: true,
  escalationPrefix: 'escalate sandbox to ',
  maxCallSites: 500,
  guard: { enabled: true, protectDshHome: false },
}

function expandTilde(value, home) {
  if (typeof value !== 'string') return value
  if (value === '~') return home
  if (value.startsWith('~/')) return home + value.slice(1)
  return value
}

/** Validate and default the plugin configuration. */
export function normalizeConfig(raw, home) {
  const input = raw !== null && typeof raw === 'object' ? raw : {}
  const guard = input.guard !== null && typeof input.guard === 'object' ? input.guard : {}
  const configured = {
    enabled: input.enabled !== false,
    storePath: typeof input.storePath === 'string' && input.storePath !== '' ? input.storePath : DEFAULT_CONFIG.storePath,
    auditPath: typeof input.auditPath === 'string' && input.auditPath !== '' ? input.auditPath : DEFAULT_CONFIG.auditPath,
    audit: input.audit !== false,
    escalationPrefix: typeof input.escalationPrefix === 'string' && input.escalationPrefix !== '' ? input.escalationPrefix : DEFAULT_CONFIG.escalationPrefix,
    maxCallSites: Number.isInteger(input.maxCallSites) && input.maxCallSites > 0 ? input.maxCallSites : DEFAULT_CONFIG.maxCallSites,
    guard: {
      enabled: guard.enabled !== false,
      protectDshHome: guard.protectDshHome === true,
    },
  }
  const dshHome = process.env.DSH_HOME !== undefined && process.env.DSH_HOME.trim() !== '' ? process.env.DSH_HOME.trim() : home + '/.dsh'
  configured.home = home
  configured.dshHome = dshHome
  configured.storePath = expandTilde(configured.storePath, home)
  configured.auditPath = expandTilde(configured.auditPath, home)
  return configured
}

export function addRule(state, spec) {
  const rule = {
    id: 'r' + state.nextId,
    path: spec.path,
    level: spec.level === 'data' ? 'data' : 'code',
    scope: spec.global === true ? 'global' : 'session',
    tools: DEFAULT_TOOLS.slice(),
    createdAt: spec.now,
    expiresAt: null,
  }
  if (rule.scope === 'session') rule.sessionId = spec.sessionId
  // 'ai' marks the rules an AI reviewer caused to exist, so the per-session cap
  // and "who widened the whitelist" stay answerable after the fact.
  if (spec.via === 'ai') rule.via = 'ai'
  state.nextId += 1
  state.rules.push(rule)
  return rule
}

export function removeRule(state, id) {
  const index = state.rules.findIndex((rule) => rule.id === id)
  if (index < 0) return undefined
  return state.rules.splice(index, 1)[0]
}

/** Rules in force for this session right now, in a deterministic order. */
export function activeRules(state, sessionId, now) {
  const live = (state.rules || []).filter((rule) => {
    if (rule.expiresAt !== null && rule.expiresAt !== undefined && rule.expiresAt <= now) return false
    if (rule.scope === 'session') return rule.sessionId === sessionId
    return true
  })
  return live.slice().sort((left, right) => (left.createdAt - right.createdAt) || (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
}

function toolAllowed(rule, tool) {
  const tools = Array.isArray(rule.tools) && rule.tools.length > 0 ? rule.tools : DEFAULT_TOOLS
  return tools.includes(tool)
}

function pathTokens(text) {
  const tokens = []
  if (typeof text !== 'string' || text === '') return tokens
  if (text.charAt(0) === '/' || text.charAt(0) === '~' || text.charAt(0) === '.' || text.charAt(0) === '\\' || /^[A-Za-z]:[\\/]/.test(text)) tokens.push(text)
  return tokens
}

function shellSpec(tool, args, sessionCwd) {
  const command = args !== null && typeof args === 'object' && typeof args.command === 'string' ? args.command : ''
  if (command === '') return { ok: false, code: 'unprovable', reason: 'no command argument to analyze' }
  const workdir = args !== null && typeof args === 'object' && typeof args.workdir === 'string' && args.workdir !== '' ? args.workdir : sessionCwd
  const analysis = analyzeCommand(command, { cwd: workdir, home: os.homedir() })
  if (analysis.opaque) return { ok: false, code: 'opaque', reason: 'command is not statically decomposable: ' + analysis.reason }
  if (analysis.destructive) return { ok: false, code: 'destructive', reason: 'command contains a deletion or move verb' }
  return { ok: true, analysis: analysis, sessionCwd: workdir }
}

function fileSpec(tool, args, sessionCwd) {
  const raw = args !== null && typeof args === 'object' ? (args.file_path !== undefined ? args.file_path : args.path) : undefined
  if (typeof raw !== 'string' || raw.trim() === '') return { ok: false, code: 'unprovable', reason: 'no file path argument' }
  return { ok: true, analysis: null, targets: [{ raw: raw.trim(), cwd: sessionCwd, glob: /[*?[]/.test(raw) }] }
}

function matchRule(rule, spec, request) {
  const root = rule.path
  const resolved = []
  if (spec.targets !== undefined) {
    for (const target of spec.targets) {
      if (target.glob) return { ok: false, code: 'unprovable', reason: 'glob write target ' + target.raw }
      const canonical = normalizePath(target.raw, target.cwd === undefined ? request.sessionCwd : target.cwd, request.home)
      if (canonical === undefined) return { ok: false, code: 'unprovable', reason: 'unresolvable target ' + target.raw }
      if (!isWithin(root, canonical)) return { ok: false, code: 'outside-root', reason: 'write target outside ' + root + ': ' + canonical }
      const link = hasSymlinkComponent(canonical)
      if (link === true) return { ok: false, code: 'symlink', reason: 'symlinked path component: ' + canonical }
      resolved.push(canonical)
    }
  }
  const segments = spec.analysis === null ? [] : spec.analysis.segments
  if (spec.analysis !== null) {
    for (const write of spec.analysis.writes) {
      if (write.glob) return { ok: false, code: 'unprovable', reason: 'glob write target ' + write.raw }
      const canonical = normalizePath(write.raw, write.cwd === undefined ? request.sessionCwd : write.cwd, request.home)
      if (canonical === undefined) return { ok: false, code: 'unprovable', reason: 'unresolvable write target ' + write.raw }
      if (!isWithin(root, canonical)) return { ok: false, code: 'outside-root', reason: 'write target outside ' + root + ': ' + canonical }
      const link = hasSymlinkComponent(canonical)
      if (link === true) return { ok: false, code: 'symlink', reason: 'symlinked path component: ' + canonical }
      resolved.push(canonical)
    }
  }

  const programs = segments.filter((segment) => segment.kind === 'program')
  if (programs.length === 0) {
    if (resolved.length === 0) return { ok: false, code: 'no-write-target', reason: 'command has no provable write target' }
    return { ok: true, code: 'allowed', level: rule.level, targets: resolved }
  }

  if (rule.level !== 'data') {
    return { ok: false, code: 'program-denied', reason: 'level code does not allow executing ' + (programs[0].program || 'a program') }
  }
  for (const segment of programs) {
    const cwd = segment.cwd === undefined ? request.sessionCwd : segment.cwd
    // Inline code (python3 -c, bash -c, ...) is behaviour, so paths hidden inside it
    // count; ordinary message text (git commit -m) is not code and is not scanned.
    const operands = (segment.operands || []).concat(segment.inlineCode || [])
    for (const operand of operands) {
      const tokens = pathTokens(operand).concat((segment.inlineCode || []).includes(operand) ? embeddedPaths(operand) : [])
      for (const token of tokens) {
        const canonical = normalizePath(token, cwd, request.home)
        if (canonical === undefined) return { ok: false, code: 'unprovable', reason: 'unresolvable program operand ' + token }
        if (!isWithin(root, canonical) && !isWithin(request.workspace, canonical)) {
          return { ok: false, code: 'outside-root', reason: 'program operand outside trusted area: ' + canonical }
        }
      }
    }
  }
  if (resolved.length === 0 && programs.length === 0) return { ok: false, code: 'no-write-target', reason: 'command has no provable write target' }
  return { ok: true, code: 'allowed', level: rule.level, targets: resolved }
}

const PRIORITY = ['allowed', 'guard', 'destructive', 'opaque', 'outside-root', 'symlink', 'program-denied', 'unprovable', 'no-write-target', 'unsupported-tool', 'no-rule']

/**
 * The write-effect model of one call, independent of any rule. Shared by decide()
 * and by the optional AI approval layer (src/ai.js), so both reason about exactly
 * the same provable targets.
 * @returns {{ok: boolean, code?: string, reason?: string, spec: object|null}}
 */
export function buildSpec(tool, args, sessionCwd) {
  if (FILE_TOOLS.has(tool)) {
    const spec = fileSpec(tool, args, sessionCwd)
    return { ok: spec.ok, code: spec.code, reason: spec.reason, spec: spec }
  }
  if (SHELL_TOOLS.has(tool)) {
    const spec = shellSpec(tool, args, sessionCwd)
    return { ok: spec.ok, code: spec.code, reason: spec.reason, spec: spec }
  }
  return { ok: false, code: 'unsupported-tool', reason: 'tool ' + tool + ' has no write-target model', spec: null }
}

/**
 * Everything the server can prove about one call, with no rule applied: the guard
 * verdict, the canonical write targets, the programs it would run, and whether the
 * call is provable at level code. Nothing here depends on a rule existing.
 */
export function analyzeCall(request) {
  const tool = String(request.tool)
  const args = request.args
  const workspace = request.workspace === undefined ? request.sessionCwd : request.workspace
  let guard
  if (request.guardEnabled !== false) {
    guard = guardReason({ name: tool, arguments: args }, { workspace: workspace, home: request.home, dshHome: request.dshHome, protectDshHome: request.protectDshHome === true })
  }
  const built = buildSpec(tool, args, request.sessionCwd)
  const spec = built.spec
  const targets = []
  const unprovable = []
  const programs = []
  if (spec !== null) {
    const raws = (spec.targets || []).concat(spec.analysis ? (spec.analysis.writes || []) : [])
    for (const target of raws) {
      if (target.glob) { unprovable.push({ raw: target.raw, reason: 'glob write target' }); continue }
      const canonical = normalizePath(target.raw, target.cwd === undefined ? request.sessionCwd : target.cwd, request.home)
      if (canonical === undefined) { unprovable.push({ raw: target.raw, reason: 'unresolvable write target' }); continue }
      if (targets.indexOf(canonical) < 0) targets.push(canonical)
    }
    if (spec.analysis) {
      for (const segment of spec.analysis.segments) {
        if (segment.kind === 'program') programs.push(String(segment.program === undefined ? 'unknown' : segment.program))
      }
    }
  }
  const destructive = built.code === 'destructive'
  const opaque = built.code === 'opaque'
  const command = args !== null && typeof args === 'object' && typeof args.command === 'string' ? args.command : ''
  return {
    tool: tool,
    guardReason: guard,
    code: guard !== undefined ? 'guard' : built.code,
    reason: guard !== undefined ? guard : built.reason,
    spec: spec,
    targets: targets,
    unprovable: unprovable,
    programs: programs,
    destructive: destructive,
    opaque: opaque,
    // Level code, restated: a call is code provable only when static analysis can
    // show every write target and there is no program whose behaviour is invisible.
    codeProvable: built.ok === true && !destructive && !opaque && programs.length === 0 && targets.length > 0,
    commandText: command,
  }
}

/**
 * Decide whether one escalation may be granted once.
 * @returns {{allow: boolean, code: string, reason: string, targets: string[], ruleId?: string, level?: string}}
 */
export function decide(request) {
  const tool = String(request.tool)
  const args = request.args
  const roots = {
    workspace: request.workspace === undefined ? request.sessionCwd : request.workspace,
    home: request.home,
    dshHome: request.dshHome,
    protectDshHome: request.protectDshHome === true,
  }
  if (request.guardEnabled !== false) {
    const hard = guardReason({ name: tool, arguments: args }, roots)
    if (hard !== undefined) return { allow: false, code: 'guard', reason: hard, targets: [] }
  }
  const built = buildSpec(tool, args, request.sessionCwd)
  if (built.spec === null) return { allow: false, code: built.code, reason: built.reason, targets: [] }
  const spec = built.spec
  if (!spec.ok) return { allow: false, code: spec.code, reason: spec.reason, targets: [] }

  const applicable = (request.rules || []).filter((rule) => toolAllowed(rule, tool))
  if (applicable.length === 0) return { allow: false, code: 'no-rule', reason: 'no rule covers tool ' + tool, targets: [] }

  let best = null
  for (const rule of applicable) {
    const result = matchRule(rule, spec, request)
    if (result.ok) return { allow: true, code: 'allowed', reason: 'matched rule ' + rule.id, targets: result.targets, ruleId: rule.id, level: rule.level }
    if (best === null || PRIORITY.indexOf(result.code) < PRIORITY.indexOf(best.code)) best = { code: result.code, reason: result.reason }
  }
  return { allow: false, code: best.code, reason: best.reason, targets: [] }
}

/** Parse and apply one /permit command line. */
export function parsePermit(rawInput) {
  const text = typeof rawInput === 'string' ? rawInput.trim() : ''
  if (text === '') return { command: 'help', args: [] }
  const parts = text.split(/\s+/)
  return { command: parts[0].toLowerCase(), args: parts.slice(1) }
}

export function describeRule(rule, now) {
  const expiry = rule.expiresAt === null || rule.expiresAt === undefined ? 'never' : new Date(rule.expiresAt).toISOString()
  return rule.id + '  level=' + rule.level + '  scope=' + rule.scope + (rule.scope === 'session' ? '(' + String(rule.sessionId).slice(0, 18) + ')' : '') + '  expires=' + expiry + '  ' + rule.path
}

export const HELP = [
  'usage:',
  '  /permit add <path> [code|data] [global]   trust a directory for provable writes',
  '  /permit list                              show the rules in force',
  '  /permit rm <id>                           remove a rule',
  '  /permit reload                            re-read the rule store from disk',
  'levels: code (default, only statically provable writes) | data (also runs programs)',
].join('\n')
