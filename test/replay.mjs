// SPDX-License-Identifier: MIT
// Acceptance replay: the 23 real escalation requests from the myproject session
// (extracted from the DSH session log by tools/extract-cases.mjs) fed straight
// into the decision engine. This is the only honest way to measure the plugin:
// session logs cannot distinguish an auto-grant from a human click.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { assert, summary, test } from './harness.mjs'
import { decide } from '../src/rules.js'
import { analyzeCommand } from '../src/targets.js'
import { isWithin } from '../src/paths.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(fs.readFileSync(path.join(here, 'cases.json'), 'utf8'))
const home = process.env.HOME
const dshHome = path.join(home, '.dsh')
const ROOT = process.argv[2] || '/home/user/myproject/data/plugins'
const workspace = doc.sessionCwd || '/mnt/d/myproject'

function rule(level) {
  return { id: 'r1', path: ROOT, level, scope: 'global', tools: ['write', 'edit', 'apply_patch', 'str_replace_editor', 'bash', 'pwsh', 'read'], createdAt: 0, expiresAt: null }
}
function run(level, item) {
  return decide({
    rules: [rule(level)],
    tool: item.tool,
    args: item.arguments,
    sessionCwd: workspace,
    workspace: workspace,
    sessionId: 'session-replay',
    home: home,
    dshHome: dshHome,
    protectDshHome: false,
    guardEnabled: true,
  })
}

console.log('== replay: ' + doc.cases.length + ' real escalation requests ==')
console.log('   rule root: ' + ROOT + '   session cwd: ' + workspace)
const rows = []
for (const item of doc.cases) {
  const code = run('code', item)
  const data = run('data', item)
  rows.push({ item, code, data })
}

const codeAllowed = rows.filter((row) => row.code.allow)
const dataAllowed = rows.filter((row) => row.data.allow)
const width = (value, size) => String(value).padEnd(size, ' ').slice(0, size)
console.log('   seq    tool   real outcome    code-level                    data-level')
for (const row of rows) {
  console.log('   ' + width(row.item.seq, 6) + ' ' + width(row.item.tool, 6) + ' ' + width(row.item.outcome, 15) + ' ' +
    width(row.code.allow ? 'ALLOW' : row.code.code, 29) + ' ' + (row.data.allow ? 'ALLOW' : row.data.code))
}
console.log('   code-level allowed: ' + codeAllowed.length + '/' + rows.length + '   data-level allowed: ' + dataAllowed.length + '/' + rows.length)

await test('every extracted case is a real sandbox escalation', () => {
  for (const item of doc.cases) assert(item.escalation === true, 'seq ' + item.seq + ' is not an escalation')
})
await test('level code never approves a write it cannot prove', () => {
  for (const row of rows) {
    if (!row.code.allow) continue
    for (const target of row.code.targets) assert(isWithin(ROOT, target), 'allowed target outside root: ' + target)
    const analysis = analyzeCommand(String(row.item.arguments.command || ''), { cwd: workspace, home })
    if (analysis.opaque === false && analysis.destructive === false) {
      for (const write of analysis.writes) assert(isWithin(ROOT, write.raw), 'allowed write outside root: ' + write.raw)
    }
  }
})
await test('level data never approves an explicit write outside the root', () => {
  for (const row of rows) {
    if (!row.data.allow) continue
    for (const target of row.data.targets) assert(isWithin(ROOT, target), 'allowed target outside root: ' + target)
  }
})
await test('level code reaches the provable subset', () => {
  assert(codeAllowed.length >= 6, 'expected the 6 file edits to be provable, got ' + codeAllowed.length)
})
await test('level data reaches the README section 9 target of 21/23', () => {
  assert(dataAllowed.length >= 21, 'expected >= 21 auto-allowed at level data, got ' + dataAllowed.length)
  assert(dataAllowed.length <= rows.length, 'cannot exceed the case count')
})
await test('the refused cases are refused for a stated reason', () => {
  for (const row of rows) {
    if (row.data.allow) continue
    assert(typeof row.data.code === 'string' && row.data.code !== 'allowed', 'missing refusal code for seq ' + row.item.seq)
    assert(typeof row.data.reason === 'string' && row.data.reason.length > 0, 'missing refusal reason for seq ' + row.item.seq)
  }
})

summary('replay')
