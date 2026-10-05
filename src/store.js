// SPDX-License-Identifier: MIT
// Rule persistence and the audit log. Both operations are fail-closed: any I/O
// failure leaves the in-memory state untouched and never throws into the tool
// pipeline.
import fs from 'node:fs'
import path from 'node:path'

export const STORE_VERSION = 1

export function emptyState() {
  return { version: STORE_VERSION, nextId: 1, rules: [] }
}

function validRule(rule) {
  if (rule === null || typeof rule !== 'object') return false
  if (typeof rule.id !== 'string' || rule.id === '') return false
  if (typeof rule.path !== 'string' || rule.path === '') return false
  if (rule.level !== 'code' && rule.level !== 'data') return false
  if (rule.scope !== 'session' && rule.scope !== 'global') return false
  if (rule.scope === 'session' && typeof rule.sessionId !== 'string') return false
  return true
}

/**
 * Read the rule store. A missing file is an empty store; a corrupt file keeps
 * the valid rules and reports the problem through onError.
 */
export function loadState(file, onError) {
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (error) {
    if (error !== null && error.code === 'ENOENT') return { state: emptyState(), existed: false }
    if (onError) onError('read rule store', file, error)
    return { state: emptyState(), existed: false }
  }
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    if (onError) onError('parse rule store', file, error)
    return { state: emptyState(), existed: true }
  }
  const state = emptyState()
  const rules = Array.isArray(parsed.rules) ? parsed.rules : []
  let dropped = 0
  for (const rule of rules) {
    if (validRule(rule)) state.rules.push(rule)
    else dropped++
  }
  state.nextId = Number.isInteger(parsed.nextId) && parsed.nextId > 0 ? parsed.nextId : state.rules.length + 1
  if (dropped > 0 && onError) onError('drop invalid rules', file, new Error(String(dropped) + ' invalid rule(s) ignored'))
  return { state: state, existed: true }
}

/** Atomic replace: write a sibling temp file, then rename over the target. */
export function saveState(file, state) {
  const directory = path.dirname(file)
  fs.mkdirSync(directory, { recursive: true })
  const temp = file + '.tmp.' + process.pid + '.' + Date.now()
  fs.writeFileSync(temp, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 })
  fs.renameSync(temp, file)
}

/** Append one audit line. Failures are reported, never thrown. */
export function appendAudit(file, entry, onError) {
  const line = JSON.stringify(entry) + '\n'
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.appendFileSync(file, line, { mode: 0o600 })
    return true
  } catch (error) {
    if (onError) onError('append audit log', file, error)
    return false
  }
}
