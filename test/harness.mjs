// SPDX-License-Identifier: MIT
// Minimal dependency-free test harness: deterministic, non-zero exit on failure.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/**
 * Scratch root shared by every suite. It deliberately lives OUTSIDE the plugin
 * tree: an installed copy under ~/.dsh/plugins is read-only to the sandbox (and
 * may be read-only in general), so writing next to the test files would make the
 * shipped suite fail from exactly the location people run it. Point AW_TEST_TMP
 * somewhere inspectable to keep the artifacts.
 */
export const SCRATCH = process.env.AW_TEST_TMP !== undefined && process.env.AW_TEST_TMP !== ''
  ? path.resolve(process.env.AW_TEST_TMP)
  : path.join(os.tmpdir(), 'dsh-approval-whitelist-tests')

/** Create (if needed) and return a directory under the scratch root. */
export function scratch(...parts) {
  const target = path.join(SCRATCH, ...parts)
  fs.mkdirSync(target, { recursive: true })
  return target
}

let passed = 0
const failures = []

export function assert(condition, message) {
  if (condition !== true) throw new Error(message || 'assertion failed')
}

export function assertEqual(actual, expected, message) {
  const left = JSON.stringify(actual)
  const right = JSON.stringify(expected)
  if (left !== right) throw new Error((message || 'not equal') + '\n    actual:   ' + left + '\n    expected: ' + right)
}

export async function test(name, fn) {
  try {
    await fn()
    passed += 1
    console.log('  PASS ' + name)
  } catch (error) {
    failures.push({ name, message: error && error.message ? error.message : String(error) })
    console.log('  FAIL ' + name + '\n       ' + (error && error.message ? error.message : String(error)))
  }
}

let reported = 0
let reportedFailures = 0
export function summary(label) {
  const suitePassed = passed - reported
  const suiteFailed = failures.length - reportedFailures
  reported = passed
  reportedFailures = failures.length
  console.log('--- ' + label + ': ' + suitePassed + ' passed, ' + suiteFailed + ' failed ---')
  if (failures.length > 0) process.exitCode = 1
  return { passed: suitePassed, failed: suiteFailed, failures }
}
