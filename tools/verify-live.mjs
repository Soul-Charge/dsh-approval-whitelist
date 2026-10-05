// SPDX-License-Identifier: MIT
// Post-install verification. Answers "is what is running actually what was
// tested, and is it still configured the way I think" without touching DSH.
//
// Usage (from the installed plugin directory):
//   node tools/verify-live.mjs [--source <project dir>]
//                              [--store <rules.json>] [--audit <audit.log>]
//                              [--session <id>]
// Exit code is non-zero when a check fails.
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const argv = process.argv.slice(2)
const opt = (name, fallback) => {
  const index = argv.indexOf(name)
  return index >= 0 && argv[index + 1] !== undefined ? argv[index + 1] : fallback
}
const SOURCE = opt('--source', '/mnt/f/workspace/projects/dsh-approval-whitelist')
const STORE = opt('--store', path.join(os.homedir(), '.dsh', 'approval-whitelist.json'))
const AUDIT = opt('--audit', path.join(os.homedir(), '.dsh', 'approval-whitelist.audit.log'))
const SESSION = opt('--session', 'verify-live')
const problems = []
const md5 = (file) => crypto.createHash('md5').update(fs.readFileSync(file)).digest('hex')

console.log('plugin under test: ' + here)

// 1) installed bytes vs the tested source tree
if (fs.existsSync(path.join(SOURCE, 'src'))) {
  const pairs = []
  for (const sub of ['src', 'test', 'tools']) {
    const from = path.join(SOURCE, sub)
    if (!fs.existsSync(from)) continue
    for (const file of fs.readdirSync(from)) {
      if (!/\.(js|mjs|json)$/.test(file)) continue
      pairs.push([path.join(from, file), path.join(here, sub, file)])
    }
  }
  let same = 0
  for (const [left, right] of pairs) {
    if (!fs.existsSync(right)) { problems.push('missing in install: ' + right); continue }
    if (md5(left) === md5(right)) same += 1
    else problems.push('differs from source: ' + right)
  }
  console.log('[1] source comparison: ' + same + '/' + pairs.length + ' files identical to ' + SOURCE)
} else {
  console.log('[1] source comparison: skipped (no source tree at ' + SOURCE + ')')
}

// 2) the module loads
const mod = await import(pathToFileURL(path.join(here, 'src/index.js')).href)
console.log('[2] module loads: name=' + mod.name + ' inject=' + JSON.stringify(mod.inject) + ' apply=' + typeof mod.apply)
if (mod.name !== 'approval-whitelist' || typeof mod.apply !== 'function') problems.push('unexpected module shape')

// 3) the rule store the running process reads
const store = await import(pathToFileURL(path.join(here, 'src/store.js')).href)
const rules = await import(pathToFileURL(path.join(here, 'src/rules.js')).href)
const loadErrors = []
const loaded = store.loadState(STORE, (operation, target, error) => loadErrors.push(operation + ' ' + target + ': ' + error.message))
console.log('[3] rule store ' + STORE)
console.log('    exists=' + loaded.existed + ' rules=' + loaded.state.rules.length + ' load errors=' + loadErrors.length)
for (const message of loadErrors) problems.push('store: ' + message)
const live = rules.activeRules(loaded.state, SESSION, Date.now())
for (const rule of live) console.log('    LIVE  ' + rules.describeRule(rule, Date.now()))
for (const rule of loaded.state.rules) {
  if (live.indexOf(rule) < 0) console.log('    idle  ' + rules.describeRule(rule, Date.now()))
}

// 4) the real cases, decided by the installed code against the live rules
const casesPath = path.join(here, 'test/cases.json')
if (fs.existsSync(casesPath)) {
  const doc = JSON.parse(fs.readFileSync(casesPath, 'utf8'))
  const home = os.homedir()
  let allowed = 0
  for (const item of doc.cases) {
    const decision = rules.decide({
      rules: live, tool: item.tool, args: item.arguments, sessionCwd: doc.sessionCwd, workspace: doc.sessionCwd,
      sessionId: SESSION, home: home, dshHome: path.join(home, '.dsh'), protectDshHome: false, guardEnabled: true,
    })
    if (decision.allow) allowed += 1
  }
  console.log('[4] replay of the ' + doc.cases.length + ' real escalation requests with the live rules: ' + allowed + ' auto-allowed')
  if (allowed === 0) problems.push('no real case is auto-allowed - the rule store is probably empty')
}

// 5) guard backstops (pure decisions, nothing is executed)
const { decide } = rules
const base = { rules: live, sessionCwd: SOURCE, workspace: SOURCE, sessionId: SESSION, home: os.homedir(), dshHome: path.join(os.homedir(), '.dsh'), protectDshHome: false, guardEnabled: true }
const backstops = [
  ['delete verb', 'bash', { command: 'rm -rf /tmp/whatever' }, 'destructive'],
  ['privilege escalation', 'bash', { command: 'sudo ls' }, 'guard'],
  ['device write', 'bash', { command: 'dd if=/dev/zero of=/dev/sda' }, 'guard'],
  ['credential store', 'write', { file_path: path.join(os.homedir(), '.ssh', 'authorized_keys') }, 'guard'],
  ['outside-root copy', 'bash', { command: 'cp /tmp/a /etc/cron.d/evil' }, 'guard'],
]
let passed = 0
for (const [label, tool, args, expected] of backstops) {
  const outcome = decide(Object.assign({}, base, { tool, args }))
  const ok = outcome.allow === false
  if (ok) passed += 1
  else problems.push('backstop failed (' + label + ')')
  console.log('[5] backstop ' + (ok ? 'OK  ' : 'FAIL') + ' ' + label + ' -> ' + (outcome.allow ? 'ALLOWED' : outcome.code) + (expected === undefined ? '' : ''))
}
console.log('    ' + passed + '/' + backstops.length + ' backstops refused')

// 6) audit log summary
if (fs.existsSync(AUDIT)) {
  const lines = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter((line) => line !== '')
  const counts = {}
  for (const line of lines) {
    try {
      const entry = JSON.parse(line)
      counts[entry.result] = (counts[entry.result] || 0) + 1
    } catch (error) { counts['<unparsable>'] = (counts['<unparsable>'] || 0) + 1 }
  }
  console.log('[6] audit ' + AUDIT + ': ' + lines.length + ' line(s) ' + JSON.stringify(counts))
} else {
  console.log('[6] audit ' + AUDIT + ': not created yet (no whitelist judgement has run)')
}

console.log(problems.length === 0 ? '\nVERDICT: all checks passed' : '\nVERDICT: ' + problems.length + ' problem(s)\n  ' + problems.join('\n  '))
process.exitCode = problems.length === 0 ? 0 : 1
