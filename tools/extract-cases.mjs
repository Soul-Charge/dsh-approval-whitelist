#!/usr/bin/env node
// Extract the real approval cases from a DSH session log into a replay fixture.
// Only the fields a decision needs are kept (tool, arguments, escalation reason,
// outcome, session cwd); credential-looking strings are redacted before writing.
import fs from 'node:fs'
import path from 'node:path'
import { readLog } from './session-cases.mjs'

const args = process.argv.slice(2)
const opt = (name, dflt) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : dflt
}
const file = opt('--file')
const out = opt('--out', 'test/cases.json')
const maxSeq = Number(opt('--max-seq', 'Infinity'))
if (!file) { console.error('usage: extract-cases.mjs --file <session.jsonl.zstd> --out <cases.json> [--max-seq N]'); process.exit(2) }

const REDACT = [
  [/sk-[A-Za-z0-9_-]{8,}/g, '<redacted-key>'],
  [/Bearer\s+[A-Za-z0-9._-]{12,}/g, 'Bearer <redacted>'],
  [/(?:token|secret|password|passwd|api[_-]?key)\s*[=:]\s*\S{8,}/gi, '$1=<redacted>'],
  [/ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '<redacted-jwt>'],
]

function redact(text) {
  let s = String(text)
  for (const [re, to] of REDACT) s = s.replace(re, to)
  return s
}

const events = readLog(file)
const header = events.find((e) => e.type === 'session') ?? {}
const bySub = new Map()
const byCall = new Map()
for (const e of events) {
  if (e.type === 'tool/ptc-dispatch') bySub.set(String(e.data?.subCallId), e.data)
  if (e.type === 'tool/call') byCall.set(String(e.data?.callId), e.data)
}
const decided = new Map()
for (const e of events) if (e.type === 'approval/decided') decided.set(String(e.data?.id), e.data?.outcome)

const cases = []
for (const e of events) {
  if (e.type !== 'approval/asked') continue
  if (Number(e.seq) > maxSeq) continue
  const d = e.data ?? {}
  const site = bySub.get(String(d.callId)) ?? byCall.get(String(d.callId))
  const rawArgs = site?.arguments ?? null
  const keep = {}
  if (rawArgs && typeof rawArgs === 'object') {
    if (typeof rawArgs.command === 'string') keep.command = redact(rawArgs.command)
    if (typeof rawArgs.workdir === 'string') keep.workdir = rawArgs.workdir
    if (typeof rawArgs.file_path === 'string') keep.file_path = rawArgs.file_path
    if (typeof rawArgs.code === 'string') keep.code = redact(rawArgs.code)
    if (rawArgs.sandbox_permissions !== undefined) keep.sandbox_permissions = rawArgs.sandbox_permissions
  }
  cases.push({
    seq: e.seq,
    tool: d.toolName,
    callId: String(d.callId),
    outcome: decided.get(String(d.id)) ?? 'pending',
    escalation: typeof d.reason === 'string' && d.reason.startsWith('escalate sandbox to '),
    reason: redact(d.reason ?? '').slice(0, 400),
    arguments: keep,
    resolved: site !== undefined,
  })
}

const doc = {
  source: path.basename(file),
  sessionCwd: header.cwd ?? null,
  extractedFrom: 'DSH session log (real escalation history)',
  note: 'Credential-looking strings redacted. arguments.command/file_path are the real call arguments.',
  cases,
}
fs.mkdirSync(path.dirname(out), { recursive: true })
fs.writeFileSync(out, JSON.stringify(doc, null, 2) + '\n')
console.log('wrote', out, 'cases:', cases.length)
console.log('resolved arguments:', cases.filter((c) => c.resolved).length, 'unresolved:', cases.filter((c) => !c.resolved).length)
const byOutcome = {}
for (const c of cases) byOutcome[c.outcome] = (byOutcome[c.outcome] ?? 0) + 1
console.log('outcomes:', JSON.stringify(byOutcome))
console.log('tools:', JSON.stringify(cases.reduce((a, c) => (a[c.tool] = (a[c.tool] ?? 0) + 1, a), {})))
// Summary only - never dump full commands into the transcript.
for (const c of cases) {
  const cmd = c.arguments.command ?? c.arguments.file_path ?? '<no-args>'
  const head = String(cmd).split(/[\s;|&]+/).filter(Boolean).slice(0, 1).join(' ')
  console.log('  seq=' + c.seq, c.tool, c.outcome, 'lead=' + head, 'len=' + String(cmd).length)
}
