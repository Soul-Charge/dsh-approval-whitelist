// SPDX-License-Identifier: MIT
// Integration test: compose the REAL cordis runtime, dsh-tools pipeline,
// dsh-user-approval service and this plugin, then drive actual escalations.
// No auto-mode is composed anywhere: this is the "auto-mode deleted" deployment.
// All state (rule store, audit log, scratch dirs) lives under the harness scratch root.
import fs from 'node:fs'
import path from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import ApprovalService from '@deepseek-ai/dsh-user-approval'
import Commands from '@deepseek-ai/dsh-commands'
import FileSettingsProvider from '@deepseek-ai/dsh-settings-file'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import * as whitelist from '../src/index.js'
import { assert, assertEqual, scratch, summary, test } from './harness.mjs'

const tmp = scratch('integration')
const trusted = path.join(tmp, 'trusted')
const ws = path.join(tmp, 'ws')
const outside = path.join(tmp, 'outside')
for (const d of [trusted, ws, outside]) fs.mkdirSync(d, { recursive: true })
const storePath = path.join(tmp, 'integration-rules.json')
const auditPath = path.join(tmp, 'integration-audit.log')

async function compose(level, options) {
  const opts = options || {}
  fs.writeFileSync(storePath, JSON.stringify({
    version: 1,
    nextId: 2,
    rules: [{ id: 'r1', path: trusted, level: level, scope: 'global', tools: ['write', 'edit', 'bash'], createdAt: 1, expiresAt: null }],
  }, null, 2))
  const context = new Context()
  context.provide('agents', { get: () => undefined })
  // The AI layer must mount without an llm service, so the service is optional here.
  if (opts.llm !== undefined) context.provide('llm', opts.llm)
  // When a case needs to prove that a Settings change reaches the reviewer, the
  // REAL settings provider is mounted (a file-backed one wrote to scratch).
  if (opts.settings === true) {
    await context.plugin(FileSettingsProvider, { path: path.join(tmp, 'integration-settings.yaml') }).await()
  }
  const session = new Session(SessionId('session-integration'), undefined, { version: 3, id: SessionId('session-integration'), createdAt: 1, isSeeded: false, cwd: ws })
  session.append('turn/start', {})
  session.append('permission/preset', { preset: 'workspace-write' })
  // A real session logs the route it is running on; when opts.sessionRoute is given
  // this reproduces that header so the AI layer can follow the session model.
  if (opts.sessionRoute !== undefined) session.append('request/header', { header: { config: opts.sessionRoute } })
  // The default stand-in agent carries a route in its options, like a real Agent whose
  // creation was given a provider/model; agentOptions lets a case remove it.
  const agentOptions = opts.agentOptions === undefined ? { provider: 'mock', model: 'mock' } : opts.agentOptions
  const agent = { options: agentOptions, session: session }

  await context.plugin(SystemPrompt).await()
  await context.plugin(ToolRuntime).await()
  await context.plugin(ApprovalService, { policy: 'ask' }).await()
  await context.plugin(Commands).await()
  await context.plugin(whitelist, {
    storePath: storePath,
    auditPath: auditPath,
    guard: { enabled: true, protectDshHome: false },
    aiReview: opts.aiReview,
  }).await()

  const state = { prompts: 0, bodies: 0 }
  const escalationTool = (name) => defineTool({
    name: name,
    description: 'integration probe: records the call and asks for a sandbox escalation',
    parameters: { command: { type: 'string' }, file_path: { type: 'string' }, sandbox_permissions: { type: 'string' }, justification: { type: 'string' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true } } }, render: () => [{ type: 'text', text: 'ok' }] },
    async execute(args, exec) {
      state.bodies += 1
      if (args.sandbox_permissions !== undefined) {
        const { approveEscalation } = await import('@deepseek-ai/dsh-sandbox')
        await approveEscalation(
          { requestedMode: args.sandbox_permissions, justification: args.justification || '', effectiveMode: 'workspace-write', subject: 'call' },
          { approver: context.get('approval'), agent: exec.agent, callId: exec.callId, toolName: name, signal: exec.signal },
        )
      }
      return { ok: true }
    },
  })
  context.tools.register(escalationTool('bash'))
  context.tools.register(escalationTool('write'))
  // Stands in for the UI / remote-gate answerer chain.
  context.on('approval/request', (request, next) => { state.prompts += 1; return next() }, { prepend: false })

  const run = async (id, name, args) => context.tools.execute({ callId: ToolCallId(id), name: name, arguments: args, agent: agent, signal: new AbortController().signal })
  return { context, agent, run, state, llm: opts.llm, dispose: async () => { await context.fiber.dispose() } }
}

/** A local stand-in for the llm service: same chunk protocol, no network. */
function fakeJudge(reply) {
  const calls = []
  return {
    calls,
    resolveCallConfig: async () => ({}),
    async *stream(options) {
      calls.push(options)
      const text = typeof reply === 'function' ? reply(options) : reply
      if (text === null) throw new Error('judge transport down')
      yield { type: 'text-delta', index: 0, text: text }
      yield { type: 'finish', reason: { kind: 'stop' } }
    },
  }
}

const AI_ON = { enabled: true, provider: 'mock-ai', model: 'judge-1', tools: ['bash', 'pwsh'], timeoutMs: 2000, maxSessionRules: 3, minScopeDepth: 3 }
const auditLines = () => fs.readFileSync(auditPath, 'utf8').trim().split('\n').map((line) => JSON.parse(line))

function isError(result) {
  if (result === undefined || result === null) return true
  if (result.isError === true) return true
  const content = Array.isArray(result.content) ? result.content : []
  return content.some((block) => String(block.text || '').startsWith('Error:'))
}

console.log('== integration (real cordis + dsh-tools + dsh-user-approval, no auto-mode) ==')
await test('a whitelisted escalation is granted without reaching the UI', async () => {
  const scene = await compose('code')
  try {
    const result = await scene.run('c1', 'bash', { command: 'echo hi > ' + trusted + '/note.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false, 'the call should succeed')
    assertEqual(scene.state.prompts, 0, 'the UI answerer must not be reached')
    assertEqual(scene.state.bodies, 1, 'the tool body must run')
  } finally { await scene.dispose() }
})

await test('an escalation outside the trusted root still reaches the UI', async () => {
  const scene = await compose('code')
  try {
    const result = await scene.run('c2', 'bash', { command: 'echo hi > ' + outside + '/note.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true, 'with no answerer the escalation must fail closed')
    assertEqual(scene.state.prompts, 1, 'the UI answerer must be reached exactly once')
  } finally { await scene.dispose() }
})

await test('level code refuses to run a program, level data grants it', async () => {
  const strict = await compose('code')
  try {
    const result = await strict.run('c3', 'bash', { command: 'python3 ' + ws + '/script.py', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true)
    assertEqual(strict.state.prompts, 1)
  } finally { await strict.dispose() }
  const loose = await compose('data')
  try {
    const result = await loose.run('c4', 'bash', { command: 'python3 ' + ws + '/script.py', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false)
    assertEqual(loose.state.prompts, 0)
  } finally { await loose.dispose() }
})

await test('an unregistered callId is never granted', async () => {
  const scene = await compose('data')
  try {
    const outcome = await scene.context.waterfall(scene.context, 'approval/request', {
      agent: scene.agent, toolName: 'bash', callId: ToolCallId('never-registered'), reason: 'escalate sandbox to danger-full-access: 插件源码在工作区之外，需要写入权限',
    }, async () => 'unavailable')
    assertEqual(outcome, 'unavailable')
    assertEqual(scene.state.prompts, 1)
  } finally { await scene.dispose() }
})

await test('the self-held guard blocks privilege escalation before the body runs', async () => {
  const scene = await compose('data')
  try {
    const result = await scene.run('c5', 'bash', { command: 'sudo cp ' + trusted + '/a /tmp/b', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true)
    assertEqual(scene.state.bodies, 0, 'the guard must stop the call before dispatch')
    assertEqual(scene.state.prompts, 0, 'nothing should even ask the user')
  } finally { await scene.dispose() }
})

await test('the audit log records the decision with the documented fields', async () => {
  const scene = await compose('code')
  try {
    await scene.run('c6', 'bash', { command: 'echo hi > ' + trusted + '/audit.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n').map((line) => JSON.parse(line))
    const allowed = lines.filter((line) => line.result === 'allowed-once')
    assert(allowed.length >= 1, 'an auto-grant must be audited')
    const entry = allowed[allowed.length - 1]
    // via/model were added with the AI review layer (AI-REVIEW-BRIEF section 4):
    // every decision line now records which of the two granted it, and which model
    // was involved. A whitelist grant always has via=rule, model=null.
    assertEqual(Object.keys(entry).sort(), ['callId', 'code', 'commitHash', 'level', 'model', 'note', 'result', 'ruleId', 'sessionId', 'target', 'tool', 'ts', 'via'].sort())
    assertEqual(entry.via, 'rule')
    assertEqual(entry.model, null)
    assertEqual(entry.ruleId, 'r1')
    assertEqual(entry.level, 'code')
    assertEqual(entry.tool, 'bash')
    assert(entry.target.indexOf(trusted + '/audit.txt') >= 0, 'the target must be recorded')
    assert(String(entry.commitHash).length === 12, 'commitHash must be the build fingerprint')
  } finally { await scene.dispose() }
})

await test('the /permit command is registered and writes a rule', async () => {
  const scene = await compose('code')
  try {
    const names = scene.context.commands.list(scene.agent).map((descriptor) => descriptor.name)
    assert(names.indexOf('permit') >= 0, '/permit must be discoverable, saw: ' + names.join(','))
    const execution = await scene.context.commands.execute(scene.agent, '/permit add ' + outside + ' data global', [], new AbortController().signal)
    assertEqual(execution.result.kind, 'success')
    assert(String(execution.result.text).indexOf('level=data') >= 0, 'the level must be reported: ' + execution.result.text)
    const stored = JSON.parse(fs.readFileSync(storePath, 'utf8'))
    assertEqual(stored.rules.length, 2)
    assertEqual(stored.rules[1].path, outside)
    assertEqual(stored.rules[1].level, 'data')
    assertEqual(stored.rules[1].scope, 'global')
    const listing = await scene.context.commands.execute(scene.agent, '/permit list', [], new AbortController().signal)
    assert(String(listing.result.text).indexOf(outside) >= 0, 'list must show the new rule')
    const removal = await scene.context.commands.execute(scene.agent, '/permit rm r1', [], new AbortController().signal)
    assertEqual(removal.result.kind, 'success')
    assertEqual(JSON.parse(fs.readFileSync(storePath, 'utf8')).rules.length, 1)
    const audited = fs.readFileSync(auditPath, 'utf8').trim().split('\n').map((line) => JSON.parse(line))
    const added = audited.filter((line) => line.result === 'rule-added')
    assert(added.length >= 1, 'widening the whitelist must be audited')
    assertEqual(added[added.length - 1].target, [outside])
    assert(audited.some((line) => line.result === 'rule-removed' && line.ruleId === 'r1'), 'removal must be audited')
  } finally { await scene.dispose() }
})

console.log('== AI review (optional layer, real cordis + a local judge stand-in) ==')
await test('an escalation the whitelist refuses is granted once by the AI', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"one narrow write"}')
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const result = await scene.run('ai1', 'bash', { command: 'echo hi > ' + outside + '/ai.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false, 'the AI grant should let the call through')
    assertEqual(scene.state.prompts, 0, 'the UI answerer must not be reached')
    assertEqual(judge.calls.length, 1, 'the judge must be consulted exactly once')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.result, 'allowed-once')
    assertEqual(entry.model, 'mock-ai/judge-1')
    assertEqual(entry.risk, 'low')
    assertEqual(entry.degraded, null)
    assertEqual(entry.sessionRule, null, 'allow-once must not create a rule')
    assertEqual(JSON.parse(fs.readFileSync(storePath, 'utf8')).rules.length, 1, 'no rule may be added')
  } finally { await scene.dispose() }
})
await test('an AI allow-session adds one code/session rule and the next call needs no model', async () => {
  const judge = fakeJudge('{"decision":"allow-session","risk":"low","reason":"same dir all session"}')
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const first = await scene.run('ai2', 'bash', { command: 'echo hi > ' + outside + '/one.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(first), false)
    const stored = JSON.parse(fs.readFileSync(storePath, 'utf8')).rules
    assertEqual(stored.length, 2)
    assertEqual(stored[1].path, outside, 'the scope root is the proven target parent, server side')
    assertEqual(stored[1].level, 'code', 'an AI rule is always level code')
    assertEqual(stored[1].scope, 'session', 'an AI rule is never global')
    assertEqual(stored[1].via, 'ai')
    assertEqual(stored[1].sessionId, 'session-integration')
    const added = auditLines().filter((line) => line.result === 'rule-added' && line.via === 'ai').pop()
    assertEqual(added.ruleId, stored[1].id)
    const second = await scene.run('ai3', 'bash', { command: 'echo hi > ' + outside + '/two.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(second), false, 'the new rule must cover the second write')
    assertEqual(judge.calls.length, 1, 'the second call is granted by the rule, not by the model')
    assertEqual(scene.state.prompts, 0)
    const viaRule = auditLines().filter((line) => line.via === 'rule' && line.result === 'allowed-once').pop()
    assertEqual(viaRule.ruleId, stored[1].id)
    // ...and it is revocable like any other rule.
    const removal = await scene.context.commands.execute(scene.agent, '/permit rm ' + stored[1].id, [], new AbortController().signal)
    assertEqual(removal.result.kind, 'success')
    assertEqual(JSON.parse(fs.readFileSync(storePath, 'utf8')).rules.length, 1)
  } finally { await scene.dispose() }
})
await test('an AI allow-session for a destructive command is downgraded and never stored', async () => {
  const judge = fakeJudge('{"decision":"allow-session","risk":"low","reason":"cleanup"}')
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const result = await scene.run('ai4', 'bash', { command: 'rm -rf ' + outside + '/junk', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false, 'allow-once is still a grant')
    assertEqual(scene.state.prompts, 0)
    assertEqual(JSON.parse(fs.readFileSync(storePath, 'utf8')).rules.length, 1, 'a destructive call must never leave a rule behind')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.degraded, 'destructive-verb')
    assertEqual(entry.sessionRule, null)
  } finally { await scene.dispose() }
})
await test('an AI allow-session for a program is downgraded and never stored', async () => {
  const judge = fakeJudge('{"decision":"allow-session","risk":"low","reason":"build"}')
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const result = await scene.run('ai5', 'bash', { command: 'python3 ' + ws + '/script.py', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false)
    assertEqual(JSON.parse(fs.readFileSync(storePath, 'utf8')).rules.length, 1, 'program execution is not code provable')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.degraded, 'program-execution')
  } finally { await scene.dispose() }
})
await test('a broken model is fail-closed: the human prompt still happens', async () => {
  const judge = fakeJudge(null)
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const result = await scene.run('ai6', 'bash', { command: 'echo hi > ' + outside + '/down.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true, 'with no answerer the escalation must fail closed')
    assertEqual(scene.state.prompts, 1, 'the human must still be asked')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.result, 'pass')
  } finally { await scene.dispose() }
})
await test('an "ask" from the model is never a grant', async () => {
  const judge = fakeJudge('{"decision":"ask","risk":"high","reason":"unknown program behaviour"}')
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const result = await scene.run('ai7', 'bash', { command: 'echo hi > ' + outside + '/ask.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true)
    assertEqual(scene.state.prompts, 1)
  } finally { await scene.dispose() }
})
await test('a guard red line is never put to the model', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"sure"}')
  const scene = await compose('code', { llm: judge, aiReview: AI_ON })
  try {
    const result = await scene.run('ai8', 'bash', { command: 'sudo cp ' + outside + '/a /tmp/b', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true)
    assertEqual(scene.state.bodies, 0, 'the guard stops the call before dispatch')
    assertEqual(judge.calls.length, 0, 'the model must not be asked about a guard red line')
  } finally { await scene.dispose() }
})
await test('aiReview disabled is byte for byte the old behaviour', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"sure"}')
  const scene = await compose('code', { llm: judge, aiReview: { enabled: false, provider: 'mock-ai', model: 'judge-1' } })
  try {
    const result = await scene.run('ai9', 'bash', { command: 'echo hi > ' + outside + '/off.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true)
    assertEqual(scene.state.prompts, 1)
    assertEqual(judge.calls.length, 0, 'a disabled AI review must make zero llm calls')
  } finally { await scene.dispose() }
})
await test('a tool outside aiReview.tools is never put to the model', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"sure"}')
  const scene = await compose('code', { llm: judge, aiReview: Object.assign({}, AI_ON, { tools: ['pwsh'] }) })
  try {
    const result = await scene.run('ai10', 'write', { file_path: outside + '/tool.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), true)
    assertEqual(judge.calls.length, 0)
  } finally { await scene.dispose() }
})
await test('the per-session cap stops further AI rules', async () => {
  const judge = fakeJudge('{"decision":"allow-session","risk":"low","reason":"same dir all session"}')
  const scene = await compose('code', { llm: judge, aiReview: Object.assign({}, AI_ON, { maxSessionRules: 1 }) })
  try {
    const roots = [path.join(outside, 'a', 'b'), path.join(outside, 'c', 'd')]
    for (const [index, root] of roots.entries()) {
      fs.mkdirSync(root, { recursive: true })
      const result = await scene.run('cap' + index, 'bash', { command: 'echo hi > ' + root + '/x.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
      assertEqual(isError(result), false)
    }
    const rules = JSON.parse(fs.readFileSync(storePath, 'utf8')).rules.filter((rule) => rule.via === 'ai')
    assertEqual(rules.length, 1, 'the cap is enforced server side')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.degraded, 'session-rule-cap')
  } finally { await scene.dispose() }
})

await test('a blank aiReview route follows the session model end to end', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"follow session"}')
  // AI_ON minus the explicit route: provider/model blank = reuse the session model.
  const sessionRoute = { provider: 'workbuddy-subscription', model: 'deepseek-v4.1-flash', reasoningEffort: 'high' }
  const scene = await compose('code', { llm: judge, sessionRoute: sessionRoute, aiReview: { enabled: true, provider: '', model: '', tools: ['bash', 'pwsh'], timeoutMs: 2000, maxSessionRules: 3, minScopeDepth: 3 } })
  try {
    const result = await scene.run('sess-model', 'bash', { command: 'echo hi > ' + outside + '/probe.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false, 'the AI grant should let the call through')
    assertEqual(judge.calls.length, 1, 'the model must be consulted once')
    assertEqual(judge.calls[0].provider, 'workbuddy-subscription', 'the session provider must be used')
    assertEqual(judge.calls[0].model, 'deepseek-v4.1-flash', 'the session model must be used')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.model, 'workbuddy-subscription/deepseek-v4.1-flash', 'the audit must name the real session route')
  } finally { await scene.dispose() }
})
await test('no session route and no configured route is fail-closed end to end', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"nope"}')
  // agent with neither a header nor options: the route cannot be resolved.
  // An agent with neither a logged header nor provider/model options: the route is unknowable.
  const scene = await compose('code', { llm: judge, agentOptions: {}, aiReview: { enabled: true, provider: '', model: '', tools: ['bash', 'pwsh'], timeoutMs: 2000, maxSessionRules: 3, minScopeDepth: 3 } })
  try {
    const result = await scene.run('no-route', 'bash', { command: 'echo hi > ' + outside + '/probe2.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(judge.calls.length, 0, 'an unresolvable route must not reach the model')
    assertEqual(scene.state.prompts, 1, 'the human prompt must still happen')
    assertEqual(isError(result), true, 'with no answerer the escalation fails closed')
  } finally { await scene.dispose() }
})

await test('a model chosen in Settings is used by the NEXT escalation (no restart)', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"ok"}')
  // Compose with the real settings service and AI review OFF in the composition entry:
  // the namespace starts disabled, exactly like a fresh install.
  const scene = await compose('code', { llm: judge, settings: true, aiReview: { enabled: false, provider: '', model: '' } })
  try {
    const before = judge.calls.length
    // 1) With AI off, an escalation the whitelist refuses must reach the human and never the model.
    await scene.run('set-off', 'bash', { command: 'echo hi > ' + outside + '/a.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(judge.calls.length, before, 'a disabled AI layer must not call the model')

    // 2) Turn it on through the REAL settings service, naming a pinned provider/model.
    const settings = scene.context.get('settings')
    assert(settings !== undefined, 'the settings service must be mounted')
    const view = settings.describe().find((entry) => entry.ns === 'approval-whitelist')
    assert(view !== undefined, 'the plugin must have registered its settings namespace')
    settings.replace('approval-whitelist', { aiReview: { enabled: true, provider: 'pinned-provider', model: 'pinned-model', tools: ['bash', 'pwsh'], timeoutMs: 2000, maxSessionRules: 3, minScopeDepth: 3 } })
    // The settings write chain is asynchronous when it touches the document.
    await new Promise((resolve) => setTimeout(resolve, 80))

    // 3) The very next escalation must now go to the model, on the chosen route.
    const result = await scene.run('set-on', 'bash', { command: 'echo hi > ' + outside + '/b.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    assertEqual(isError(result), false, 'the AI grant should let the call through')
    assert(judge.calls.length > before, 'the model must now be consulted — no restart happened')
    const last = judge.calls[judge.calls.length - 1]
    assertEqual(last.provider, 'pinned-provider', 'the provider chosen in Settings must be used')
    assertEqual(last.model, 'pinned-model', 'the model chosen in Settings must be used')
    const entry = auditLines().filter((line) => line.via === 'ai').pop()
    assertEqual(entry.model, 'pinned-provider/pinned-model', 'the audit must name the settings route')
  } finally { await scene.dispose() }
})
await test('a Settings change from pinned back to follow-the-session takes effect', async () => {
  const judge = fakeJudge('{"decision":"allow-once","risk":"low","reason":"ok"}')
  const scene = await compose('code', { llm: judge, settings: true, sessionRoute: { provider: 'session-p', model: 'session-m' }, aiReview: { enabled: true, provider: 'pinned-provider', model: 'pinned-model', tools: ['bash'], timeoutMs: 2000 } })
  try {
    const settings = scene.context.get('settings')
    settings.replace('approval-whitelist', { aiReview: { enabled: true, provider: '', model: '', tools: ['bash'], timeoutMs: 2000, maxSessionRules: 3, minScopeDepth: 3 } })
    await new Promise((resolve) => setTimeout(resolve, 80))
    await scene.run('back-to-session', 'bash', { command: 'echo hi > ' + outside + '/c.txt', sandbox_permissions: 'danger-full-access', justification: 'integration' })
    const last = judge.calls[judge.calls.length - 1]
    assertEqual(last.provider, 'session-p', 'an empty settings route must fall back to the session model')
    assertEqual(last.model, 'session-m')
  } finally { await scene.dispose() }
})

summary('integration')
