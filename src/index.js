// SPDX-License-Identifier: MIT
// dsh-approval-whitelist: make pre-approved trusted-directory writes stop asking.
//
// Three registrations (taskbook section 3 and 7):
//   1. tools/pre-execute  {append:true}  - register callId -> {tool, arguments}. Never
//      returns a decision: short-circuiting pre-execute would skip the registration
//      listeners of plugins mounted after us (spike report section 4.7) and would cut
//      auto-mode's listener-level denies without replacing them.
//   2. approval/request   {prepend:true} - the only place a prompt is actually saved:
//      an escalation is granted once when its own callId is registered and the call's
//      write targets are all provable inside a trusted root.
//   3. ctx.tools.guard()                 - self-held monotonic hard deny.
//
// Zero coupling: no auto-mode module is imported, so deleting auto-mode leaves this
// plugin working.
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { appendAudit, emptyState, loadState, saveState } from './store.js'
import { HELP, activeRules, addRule, analyzeCall, decide, describeRule, normalizeConfig, parsePermit, removeRule } from './rules.js'
import { guardReason } from './guard.js'
import { AiReviewer, aiUsable, buildFacts, enforceAiDecision, normalizeAiConfig } from './ai.js'
import { installSettings, settingsEntry } from './settings.js'
import { isFilesystemRoot, normalizePath } from './paths.js'

export const name = 'approval-whitelist'
export const inject = ['tools']

function sessionIdOf(agent) {
  if (agent === null || typeof agent !== 'object') return undefined
  if (agent.session !== null && typeof agent.session === 'object' && agent.session.id !== undefined) return String(agent.session.id)
  return undefined
}

function sessionCwdOf(agent) {
  if (agent === null || typeof agent !== 'object') return undefined
  const session = agent.session
  if (session === null || typeof session !== 'object') return undefined
  // The live Session exposes its validated SessionHeader; older/projection shapes
  // may carry the same field as meta.
  const header = session.header !== null && typeof session.header === 'object' ? session.header : session.meta
  if (header !== null && typeof header === 'object' && typeof header.cwd === 'string') return header.cwd
  return undefined
}

function callIdOf(execution) {
  const value = execution !== null && typeof execution === 'object' ? execution.callId : undefined
  return value === undefined || value === null ? undefined : String(value)
}

/** Identifies the exact plugin build that made a decision (audit field commitHash). */
function buildFingerprint() {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const hash = crypto.createHash('sha256')
  let files = []
  try {
    files = fs.readdirSync(here).filter((file) => file.endsWith('.js')).sort()
  } catch (error) {
    return 'unknown'
  }
  for (const file of files) {
    try {
      hash.update(file)
      hash.update(fs.readFileSync(path.join(here, file)))
    } catch (error) {
      return 'unknown'
    }
  }
  return hash.digest('hex').slice(0, 12)
}

export function apply(ctx, config) {
  const cfg = normalizeConfig(config, os.homedir())
  // The AI layer is off unless it is switched on AND given a model. It is kept
  // out of the static inject list on purpose: a profile without dsh-llm must
  // still be able to mount this plugin.
  cfg.aiReview = normalizeAiConfig(config !== null && typeof config === 'object' ? config.aiReview : undefined)
  // The settings namespace folds the composition entry with the user layer, so a
  // model chosen in Settings takes effect without editing cordis.patch.yml.
  // aiReview() re-reads it on every escalation, which means a settings change
  // applies to the next request rather than needing a restart.
  let settingsRead = () => settingsEntry(config)
  const aiReviewNow = () => normalizeAiConfig(settingsRead().aiReview)
  let reviewer = null
  const prefix = '[approval-whitelist] '
  const log = (level, message) => {
    try {
      if (ctx.logger !== null && typeof ctx.logger === 'object' && typeof ctx.logger[level] === 'function') ctx.logger[level](prefix + message)
      else if (level === 'error' || level === 'warn') console.error(prefix + message)
    } catch (error) { /* logging must never break the pipeline */ }
  }
  if (!cfg.enabled) {
    log('info', 'disabled by configuration (enabled: false)')
    return
  }

  const callsites = new Map()
  const fingerprint = buildFingerprint()
  let state = emptyState()
  let storeMtime = -1

  const onError = (operation, target, error) => {
    log('warn', operation + ' failed for ' + target + ': ' + (error !== null && error !== undefined && error.message !== undefined ? error.message : String(error)))
  }

  const storeMtimeNow = () => {
    try {
      return fs.statSync(cfg.storePath).mtimeMs
    } catch (error) {
      return -1
    }
  }
  const reload = (initial) => {
    state = loadState(cfg.storePath, onError).state
    storeMtime = storeMtimeNow()
    if (!initial) log('info', 'rule store reloaded (' + state.rules.length + ' rule(s))')
  }
  const ensureFresh = () => {
    const mtime = storeMtimeNow()
    if (mtime !== storeMtime) reload(false)
  }

  reload(true)
  log('info', 'active: ' + state.rules.length + ' rule(s), store ' + cfg.storePath + ', build ' + fingerprint)

  // 1) Registration only. Returning next() keeps every downstream listener running.
  ctx.on('tools/pre-execute', (execution, next) => {
    const callId = callIdOf(execution)
    if (callId !== undefined) {
      callsites.set(callId, {
        tool: String(execution.name),
        args: execution.arguments,
        sessionId: sessionIdOf(execution.agent),
        sessionCwd: sessionCwdOf(execution.agent),
        time: Date.now(),
      })
      while (callsites.size > cfg.maxCallSites) {
        const oldest = callsites.keys().next()
        if (oldest.done === true) break
        callsites.delete(oldest.value)
      }
    }
    return next()
  }, { append: true })

  ctx.on('tools/result', (execution) => {
    const callId = callIdOf(execution)
    if (callId !== undefined) callsites.delete(callId)
  })

  // 3) Self-held hard deny.
  if (cfg.guard.enabled) {
    ctx.tools.guard((execution) => guardReason(execution, {
      workspace: sessionCwdOf(execution.agent) === undefined ? process.cwd() : sessionCwdOf(execution.agent),
      home: cfg.home,
      dshHome: cfg.dshHome,
      protectDshHome: cfg.guard.protectDshHome,
    }))
    log('info', 'hard-deny guard registered (protectDshHome=' + String(cfg.guard.protectDshHome) + ')')
  }

  // 1b) Optional AI review. The llm service is injected, never required: no
  // service, an unnamed route, or a module that will not import all mean the
  // reviewer stays null and every escalation behaves exactly as it did before.
  const aiRulesFor = (sessionId) => state.rules.filter((rule) => rule.via === 'ai' && rule.scope === 'session' && rule.sessionId === sessionId).length
  // Settings are installed before the reviewer is built so the armed log line
  // reports the effective configuration, not just the composition entry.
  settingsRead = installSettings(ctx, settingsEntry(config), onError)
  cfg.aiReview = aiReviewNow()
  // The llm service is injected regardless of whether AI review is enabled right
  // now: a settings change can turn it on later, and rebuilding the reviewer on
  // each escalation is what makes that take effect without a restart.
  let llmRuntime
  if (typeof ctx.inject === 'function') {
    ctx.inject(['llm'], (llmCtx) => {
      llmRuntime = llmCtx !== null && typeof llmCtx === 'object'
        ? (llmCtx.llm !== undefined ? llmCtx.llm : (typeof llmCtx.get === 'function' ? llmCtx.get('llm') : undefined))
        : undefined
      if (llmRuntime === undefined || llmRuntime === null) {
        log('warn', 'the llm service exposes no runtime; AI review falls back to the human prompt')
        return
      }
      log('info', 'llm runtime bound for AI review')
    })
  }
  /**
   * Rebuild the reviewer from the CURRENT settings. Called per escalation so a
   * model chosen in Settings applies to the next request, not the next restart.
   */
  const reviewerNow = () => {
    const live = aiReviewNow()
    cfg.aiReview = live
    if (llmRuntime === undefined || llmRuntime === null) return null
    if (!aiUsable(live)) return null
    return new AiReviewer({ llm: llmRuntime, config: live, log: log })
  }
  reviewer = reviewerNow()
  if (reviewer !== null) {
    log('info', 'AI review armed on ' + reviewer.label + ' (session rules: level=code scope=session, max ' + cfg.aiReview.maxSessionRules + '/session)')
  } else if (cfg.aiReview.enabled === true) {
    log('warn', 'AI review is enabled but no llm runtime is bound yet; escalations fall back to the human prompt')
  }

  // 2) The prompt-saving seam. Async because the optional AI branch may need a
  // model round trip; dsh-user-approval awaits the waterfall result.
  ctx.on('approval/request', async (request, next) => {
    // Rule edits must take effect without a restart, so re-read the store whenever
    // its mtime moved - independent of whether auditing is on.
    ensureFresh()
    const callId = request !== null && request.callId !== undefined && request.callId !== null ? String(request.callId) : undefined
    const site = callId === undefined ? undefined : callsites.get(callId)
    if (site === undefined) return next()
    const reason = typeof request.reason === 'string' ? request.reason : ''
    // Structural classification only: the reason text is never evidence of safety.
    if (!reason.startsWith(cfg.escalationPrefix)) return next()
    if (site.sessionId !== undefined) {
      const asked = sessionIdOf(request.agent)
      if (asked !== undefined && asked !== site.sessionId) return next()
    }
    // Prefer the live values carried by the approval request: a run_code sub-dispatch
    // may reach pre-execute without an agent, while the approval always has one.
    const sessionId = sessionIdOf(request.agent) === undefined ? site.sessionId : sessionIdOf(request.agent)
    const sessionCwd = sessionCwdOf(request.agent) === undefined ? site.sessionCwd : sessionCwdOf(request.agent)
    const live = activeRules(state, sessionId, Date.now())
    const decision = decide({
      rules: live,
      tool: site.tool,
      args: site.args,
      sessionCwd: sessionCwd,
      sessionId: sessionId,
      workspace: sessionCwd,
      home: cfg.home,
      dshHome: cfg.dshHome,
      protectDshHome: cfg.guard.protectDshHome,
      guardEnabled: cfg.guard.enabled,
    })
    if (cfg.audit) {
      appendAudit(cfg.auditPath, {
        ts: Date.now(),
        callId: callId === undefined ? null : callId,
        ruleId: decision.ruleId === undefined ? null : decision.ruleId,
        level: decision.level === undefined ? null : decision.level,
        result: decision.allow ? 'allowed-once' : 'pass',
        target: decision.targets,
        commitHash: fingerprint,
        tool: site.tool,
        sessionId: sessionId === undefined ? null : sessionId,
        code: decision.code,
        note: decision.reason,
        via: 'rule',
        model: null,
      }, onError)
    }
    if (decision.allow) {
      log('info', 'allowed-once ' + site.tool + ' via ' + decision.ruleId + ' (' + decision.level + '): ' + decision.targets.join(', '))
      return 'allowed-once'
    }
    // A guard red line is final: the model is never asked, because it could only
    // ever be told no (taskbook section 3.4).
    if (decision.code === 'guard') {
      log('info', 'pass ' + site.tool + ' (guard): ' + decision.reason)
      return next()
    }

    // Whitelist said no. The AI gets one look, and only for the tools it is
    // configured for; everything it can possibly grant is decided server side.
    let outcome
    // Rebuild from live settings: a model picked in Settings applies here, at the
    // next escalation, without a host restart.
    const liveReviewer = reviewerNow()
    if (liveReviewer !== null && liveReviewer.available === true && cfg.aiReview.tools.indexOf(site.tool) >= 0) {
      const call = analyzeCall({
        tool: site.tool,
        args: site.args,
        sessionCwd: sessionCwd,
        sessionId: sessionId,
        workspace: sessionCwd,
        home: cfg.home,
        dshHome: cfg.dshHome,
        protectDshHome: cfg.guard.protectDshHome,
        guardEnabled: cfg.guard.enabled,
      })
      if (call.guardReason === undefined) {
        const facts = buildFacts(call, { sessionWorkspace: sessionCwd, ruleRoots: live.map((rule) => rule.path), config: cfg.aiReview })
        // The route follows the session model unless the config overrides it, so the
        // reviewer gets the live agent and reports back which model actually ruled.
        const verdict = await liveReviewer.review(facts, request.agent)
        outcome = enforceAiDecision(verdict, call, {
          home: cfg.home,
          dshHome: cfg.dshHome,
          workspace: sessionCwd,
          protectDshHome: cfg.guard.protectDshHome,
          sessionId: sessionId,
          aiRuleCount: aiRulesFor(sessionId),
          minScopeDepth: cfg.aiReview.minScopeDepth,
          maxSessionRules: cfg.aiReview.maxSessionRules,
        })
        outcome.verdict = verdict
        outcome.call = call
        outcome.ruleId = null
        // The route the model actually ran on (audit must name it, not blank).
        const routeLabel = typeof verdict.route === 'string' && verdict.route !== '' ? verdict.route : liveReviewer.labelFor(undefined)
        outcome.routeLabel = routeLabel
        // A session rule is created only after the safety layer cleared it. The
        // level and the scope are constants, never anything the model chose.
        if (outcome.grant === true && outcome.sessionRule !== undefined) {
          const created = addRule(state, {
            path: outcome.sessionRule.path,
            level: outcome.sessionRule.level,
            global: false,
            sessionId: outcome.sessionRule.sessionId,
            now: Date.now(),
            via: 'ai',
          })
          if (save()) {
            outcome.ruleId = created.id
            if (cfg.audit) appendAudit(cfg.auditPath, {
              ts: Date.now(), callId: callId === undefined ? null : callId, ruleId: created.id, level: created.level,
              result: 'rule-added', target: [created.path], commitHash: fingerprint, tool: site.tool,
              sessionId: sessionId === undefined ? null : sessionId, code: created.scope,
              note: 'scope ' + created.scope + ', added by ai review ' + routeLabel, via: 'ai', model: routeLabel,
            }, onError)
          } else {
            // The standing grant could not be persisted, so it is withdrawn. The
            // one-shot grant stands on its own.
            removeRule(state, created.id)
            outcome.degraded = 'rule-store-unwritable'
            outcome.sessionRule = undefined
            outcome.reason = 'ai session rule withdrawn (the rule store could not be written); ' + outcome.reason
          }
        }
      }
    }

    if (outcome === undefined) {
      log('info', 'pass ' + site.tool + ' (' + decision.code + '): ' + decision.reason)
      return next()
    }
    if (cfg.audit) {
      appendAudit(cfg.auditPath, {
        ts: Date.now(),
        callId: callId === undefined ? null : callId,
        ruleId: outcome.ruleId === null ? null : outcome.ruleId,
        level: outcome.level === null || outcome.level === undefined ? null : outcome.level,
        result: outcome.grant ? 'allowed-once' : 'pass',
        target: outcome.call.targets,
        commitHash: fingerprint,
        tool: site.tool,
        sessionId: sessionId === undefined ? null : sessionId,
        code: outcome.code,
        note: outcome.reason,
        via: 'ai',
        model: outcome.routeLabel === undefined ? liveReviewer.labelFor(undefined) : outcome.routeLabel,
        risk: outcome.risk === undefined ? null : outcome.risk,
        degraded: outcome.degraded === undefined ? null : outcome.degraded,
        sessionRule: outcome.sessionRule === undefined ? null : outcome.sessionRule.path,
      }, onError)
    }
    if (!outcome.grant) {
      log('info', 'pass ' + site.tool + ' (ai ask): ' + outcome.reason)
      return next()
    }
    log('info', 'allowed-once ' + site.tool + ' via ai ' + (outcome.routeLabel === undefined ? liveReviewer.labelFor(undefined) : outcome.routeLabel) + (outcome.degraded === undefined ? '' : ' [' + outcome.degraded + ']') + (outcome.ruleId === null ? '' : ' + rule ' + outcome.ruleId) + ': ' + outcome.call.targets.join(', '))
    return 'allowed-once'
  }, { prepend: true })

  // Self-check asked for by the spike report (section 4.2): our approval listener must
  // run before auto-mode's, otherwise auto-mode's own grants decide first.
  try {
    const hooks = ctx.events !== null && typeof ctx.events === 'object' && ctx.events._hooks !== undefined ? ctx.events._hooks : undefined
    const list = hooks !== null && hooks !== undefined && typeof hooks.get === 'function' ? hooks.get('approval/request') : undefined
    if (Array.isArray(list)) {
      const selfIndex = list.findIndex((entry) => entry !== null && typeof entry === 'object' && entry.ctx === ctx)
      log('info', 'approval/request prepend position: ' + String(selfIndex) + ' of ' + String(list.length))
    } else log('info', 'approval/request prepend position: unknowable here (no hook introspection)')
  } catch (error) {
    log('info', 'approval/request prepend position: unknowable here (' + String(error && error.message) + ')')
  }

  const save = () => {
    try {
      saveState(cfg.storePath, state)
      storeMtime = storeMtimeNow()
      return true
    } catch (error) {
      onError('write rule store', cfg.storePath, error)
      return false
    }
  }

  const handlePermit = (invocation) => {
    const parsed = parsePermit(invocation !== null && invocation !== undefined ? invocation.rawInput : '')
    const sessionId = sessionIdOf(invocation !== null && invocation !== undefined ? invocation.agent : undefined)
    if (parsed.command === 'help') return { kind: 'success', text: HELP }
    if (parsed.command === 'list') {
      ensureFresh()
      const live = activeRules(state, sessionId, Date.now())
      if (state.rules.length === 0) return { kind: 'success', text: 'no rules yet. ' + HELP }
      const lines = state.rules.map((rule) => (live.includes(rule) ? '* ' : '  ') + describeRule(rule, Date.now()))
      return { kind: 'success', text: lines.join('\n') }
    }
    if (parsed.command === 'reload') {
      reload(false)
      return { kind: 'success', text: 'reloaded ' + state.rules.length + ' rule(s) from ' + cfg.storePath }
    }
    if (parsed.command === 'rm') {
      const id = parsed.args[0]
      if (id === undefined) return { kind: 'error', text: 'usage: /permit rm <id>' }
      const removed = removeRule(state, id)
      if (removed === undefined) return { kind: 'error', text: 'no rule with id ' + id }
      if (!save()) return { kind: 'error', text: 'removed ' + id + ' in memory, but the store could not be written' }
      if (cfg.audit) appendAudit(cfg.auditPath, {
        ts: Date.now(), callId: null, ruleId: removed.id, level: removed.level, result: 'rule-removed',
        target: [removed.path], commitHash: fingerprint, tool: '/permit',
        sessionId: sessionId === undefined ? null : sessionId, code: removed.scope, note: 'scope ' + removed.scope,
      }, onError)
      return { kind: 'success', text: 'removed ' + id + ' (' + removed.path + ')' }
    }
    if (parsed.command === 'add') {
      const rawPath = parsed.args[0]
      if (rawPath === undefined) return { kind: 'error', text: 'usage: /permit add <path> [code|data] [global]' }
      const flags = parsed.args.slice(1).map((value) => value.toLowerCase())
      const level = flags.includes('data') ? 'data' : 'code'
      const global = flags.includes('global')
      if (flags.some((value) => value !== 'data' && value !== 'code' && value !== 'global' && value !== 'session')) {
        return { kind: 'error', text: 'unknown option. ' + HELP }
      }
      if (global === false && sessionId === undefined) return { kind: 'error', text: 'this session has no id; add "global" to persist the rule' }
      const canonical = normalizePath(rawPath, undefined, cfg.home)
      if (canonical === undefined || !canonical.startsWith('/')) return { kind: 'error', text: 'path must be absolute: ' + rawPath }
      if (isFilesystemRoot(canonical)) return { kind: 'error', text: 'refusing to trust a filesystem root: ' + canonical }
      const rule = addRule(state, { path: canonical, level: level, global: global, sessionId: sessionId, now: Date.now() })
      if (!save()) return { kind: 'error', text: 'added ' + rule.id + ' in memory, but the store could not be written' }
      // Rule mutations are audited too: a rule is a standing trust declaration, so
      // "who widened the whitelist and when" must be answerable after the fact.
      if (cfg.audit) appendAudit(cfg.auditPath, {
        ts: Date.now(), callId: null, ruleId: rule.id, level: rule.level, result: 'rule-added',
        target: [rule.path], commitHash: fingerprint, tool: '/permit',
        sessionId: sessionId === undefined ? null : sessionId, code: rule.scope, note: 'scope ' + rule.scope,
      }, onError)
      return { kind: 'success', text: 'added ' + rule.id + ': level=' + rule.level + ' scope=' + rule.scope + ' path=' + rule.path }
    }
    return { kind: 'error', text: 'unknown subcommand "' + parsed.command + '". ' + HELP }
  }

  if (typeof ctx.inject === 'function') {
    ctx.inject(['commands'], (commandCtx) => {
      commandCtx.commands.register({
        name: 'permit',
        description: 'Manage trusted-path rules for the approval whitelist (trusted directories stop prompting)',
        input: { hint: 'add <path> [code|data] [global] | list | rm <id> | reload' },
        handler: (invocation) => handlePermit(invocation),
      })
      log('info', '/permit command registered')
    })
  } else {
    log('info', 'no command service available; /permit is not registered')
  }
}
