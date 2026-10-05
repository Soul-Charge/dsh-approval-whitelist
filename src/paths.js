// SPDX-License-Identifier: MIT
// Self-contained path canonicalization for dsh-approval-whitelist.
//
// No @nanmicoder/dsh-auto-mode module is imported or copied: the plugin must keep
// working after auto-mode is deleted (taskbook section 7). Containment is purely
// lexical (no symlink following) plus one realpath guard, see hasSymlinkComponent.
import fs from 'node:fs'
import { posix, win32 } from 'node:path'

const WSL_MNT = /^\/mnt\/([a-z])\/(.*)$/
const DRIVE_PATH = /^([a-z]):\\(.*)$/

/** Strip Win32/NT namespace prefixes before any containment decision. */
export function stripNamespace(input) {
  const lower = input.toLowerCase()
  if (lower.startsWith('\\\\?\\unc\\')) return '\\\\' + input.slice(8)
  if (lower.startsWith('\\\\?\\')) return input.slice(4)
  if (lower.startsWith('\\\\??\\')) return input.slice(5)
  if (lower.startsWith('\\??\\')) return input.slice(4)
  return input
}

/** Namespace spellings that name a device or NT object, never a file. */
export function deviceNamespace(input) {
  const p = input.replaceAll('/', '\\').toLowerCase()
  if (p.startsWith('\\\\.\\')) return 'windows device namespace ' + input
  if (p.startsWith('\\device\\') || p.startsWith('\\global??\\') || p.startsWith('\\dosdevices\\')) return 'windows NT object namespace ' + input
  if (p.startsWith('\\\\?\\') && !/^\\\\\?\\(?:unc\\|[a-z]:\\)/.test(p)) return 'windows extended device namespace ' + input
  if ((p.startsWith('\\??\\') || p.startsWith('\\\\??\\')) && !/^(?:\\\?\?\\|\\\\\?\?\\)(?:unc\\|[a-z]:\\)/.test(p)) return 'windows NT device namespace ' + input
  return undefined
}

function styleOf(value) {
  const canonical = stripNamespace(value)
  if (/^[A-Za-z]:/.test(canonical) || canonical.startsWith('\\')) return 'win32'
  if (canonical.startsWith('/')) return 'posix'
  return undefined
}

function apiOf(style) {
  return style === 'win32' ? win32 : posix
}

/** Win32 treats trailing dots/spaces as insignificant; keep both sides equal. */
function trimWindowsSegments(value) {
  const root = win32.parse(value).root
  const tail = value.slice(root.length).split('\\').map((segment) => segment.replace(/[ .]+$/, '')).join('\\')
  return tail === '' ? root : root + tail
}

/**
 * Normalize one path without touching the filesystem and without following
 * symlinks. Returns undefined when a relative path has no usable cwd.
 */
export function normalizePath(input, cwd, home) {
  if (typeof input !== 'string') return undefined
  const trimmed = input.trim()
  if (trimmed === '') return undefined
  const raw = stripNamespace(trimmed)
  let expanded = raw
  if (typeof home === 'string' && (raw === '~' || raw.startsWith('~/') || raw.startsWith('~\\'))) {
    expanded = raw === '~' ? home : apiOf(styleOf(home) || 'posix').join(home, raw.slice(2))
  }
  const style = styleOf(expanded) || (typeof cwd === 'string' ? styleOf(cwd) : undefined) || (process.platform === 'win32' ? 'win32' : 'posix')
  const api = apiOf(style)
  const absolute = api.isAbsolute(expanded) ? expanded : (typeof cwd === 'string' ? api.resolve(cwd, expanded) : undefined)
  if (absolute === undefined) return undefined
  const normalized = api.normalize(absolute)
  return style === 'win32' ? trimWindowsSegments(normalized).toLowerCase() : normalized
}

/** Spellings that name the same location: WSL /mnt/c/... equals C:\ on Windows. */
export function variants(value) {
  if (typeof value !== 'string') return []
  const mnt = WSL_MNT.exec(value)
  if (mnt !== null) return [value, mnt[1].toUpperCase() + ':\\' + mnt[2].replaceAll('/', '\\')]
  const drive = DRIVE_PATH.exec(value)
  if (drive !== null) return [value, '/mnt/' + drive[1] + '/' + drive[2].replaceAll('\\', '/')]
  return [value]
}

/** Whether target equals root or is contained below it. */
export function isWithin(root, target) {
  if (typeof root !== 'string' || typeof target !== 'string') return false
  const roots = variants(root)
  const targets = variants(target)
  for (const left of roots) {
    const style = styleOf(left)
    if (style === undefined) continue
    const api = apiOf(style)
    for (const right of targets) {
      if (styleOf(right) !== style) continue
      const relative = api.relative(left, right)
      if (relative === '' || (relative !== '..' && !relative.startsWith('..' + api.sep) && !api.isAbsolute(relative))) return true
    }
  }
  return false
}

/** Whether a path is a POSIX, drive or UNC filesystem root. */
export function isFilesystemRoot(target) {
  if (typeof target !== 'string') return false
  const style = styleOf(target)
  if (style === undefined) return false
  return apiOf(style).parse(target).root === target
}

/** Real filesystem spelling for a canonical value (WSL: drive paths live under /mnt). */
export function toFsPath(value) {
  const drive = DRIVE_PATH.exec(value)
  if (drive !== null && process.platform !== 'win32') return '/mnt/' + drive[1] + '/' + drive[2].replaceAll('\\', '/')
  return value
}

/**
 * Whether reaching the target traverses a symlink. Containment elsewhere is
 * lexical, so a symlinked component inside a trusted root can point outside it;
 * such a target is not provable and is never auto-allowed. Returns undefined
 * when the filesystem cannot answer.
 */
export function hasSymlinkComponent(canonicalTarget) {
  const real = toFsPath(canonicalTarget)
  if (typeof real !== 'string' || !real.startsWith('/')) return undefined
  const parts = real.split('/').filter(Boolean)
  let current = ''
  for (const part of parts) {
    current = current + '/' + part
    let info
    try {
      info = fs.lstatSync(current)
    } catch (error) {
      return false
    }
    if (info.isSymbolicLink()) return true
  }
  return false
}
