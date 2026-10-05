// SPDX-License-Identifier: MIT
// Self-contained monotonic hard-deny guard (taskbook section 7: the plugin must
// carry its own guard instead of relying on auto-mode being installed).
//
// Scope note: auto-mode's guard also hard-denies the DSH_HOME tree. That is an
// opt-in here (guard.protectDshHome) because this workspace's own AGENTS.md has
// the agent write ~/.dsh files through an approval escalation; denying them by
// default would silently break a documented workflow. Everything genuinely
// dangerous (privilege escalation, device/NT namespaces, filesystem roots, the
// user-home root, system trees, credential stores, private keys, exfiltration)
// is denied unconditionally.
import { deviceNamespace, isFilesystemRoot, isWithin, normalizePath } from './paths.js'
import { analyzeCommand, embeddedPaths } from './targets.js'

const PRIVILEGE_RE = /(?:^|[\s;&|()"'])(?:sudo|doas|pkexec|su)(?:\s|$)/
const OS_DAMAGE_RE = /(?:^|[\s;&|()"'])(?:mkfs(?:\.[a-z0-9]+)?|fdisk|parted|diskpart|format|wipefs|shutdown|reboot|bcdedit)(?:\s|$)/
const EXFIL_RE = /(?:--data(?:-binary|-raw|-urlencode)?|--upload-file|-F|-T|-d)\s*@/
const NETWORK_RE = /(?:^|[\s;&|()"'])(?:curl|wget|invoke-webrequest|invoke-restmethod)(?:\s|$)/
const PRIVATE_KEY_RE = /(?:^|\/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|identity|key4\.db|logins\.json|Login Data|keystore|credentials|[^/]*\.(?:pem|key|pfx|p12|kdbx|credentials\.ya?ml|env|netrc|npmrc))$/
const CREDENTIAL_DIR_RE = /(?:^|\/)(?:\.ssh|\.gnupg|\.aws|\.azure|\.kube|\.pki|\.password-store|\.cert|\.ssl|\.docker|\.config\/(?:gcloud|gh)|\.netrc|\.npmrc|\.git-credentials)(?:\/|$)/
const DEVICE_FILE_RE = /^\/dev\/(?:sd|hd|nvme|vd|xvd|mmcblk|loop|dm-|sr|disk\/|mapper\/)/
const CRITICAL_POSIX = ['/etc', '/bin', '/sbin', '/usr', '/boot', '/system', '/library', '/private/etc']
const CRITICAL_WIN_RE = /^[a-z]:\\(?:windows|window~[0-9]+|program files|program files \(x86\)|programdata|progra~[0-9]+|boot)(?:\\|$)/

const FILE_TOOLS = new Set(['write', 'edit', 'apply_patch', 'str_replace_editor', 'read', 'read_image'])
const SHELL_TOOLS = new Set(['bash', 'pwsh', 'terminal'])

function pathArgument(args) {
  if (args === null || typeof args !== 'object') return undefined
  const candidate = args.file_path !== undefined ? args.file_path : args.path
  return typeof candidate === 'string' && candidate.trim() !== '' ? candidate.trim() : undefined
}

/** A token that can only be a filesystem location (never a flag or plain word). */
function pathCandidate(word) {
  if (typeof word !== 'string' || word === '') return null
  if (word.charAt(0) === '/') return word
  if (word.charAt(0) === '~') return word
  if (/^[A-Za-z]:[\\/]/.test(word)) return word
  if (word.startsWith('\\')) return word
  if (word.charAt(0) === '.') return word
  return null
}

/** Guard rules for one concrete path, in write position. */
export function targetReason(raw, roots) {
  const namespace = deviceNamespace(raw)
  if (namespace !== undefined) return namespace
  const canonical = normalizePath(raw, roots.workspace, roots.home)
  if (canonical === undefined) return undefined
  if (DEVICE_FILE_RE.test(canonical)) return 'block device path ' + canonical
  if (isFilesystemRoot(canonical)) return 'filesystem root ' + canonical
  if (canonical === roots.home) return 'user home root ' + canonical
  if (CREDENTIAL_DIR_RE.test(canonical)) return 'credential store ' + canonical
  if (PRIVATE_KEY_RE.test(canonical)) return 'private key or credential file ' + canonical
  if (roots.protectDshHome === true && roots.dshHome !== undefined && isWithin(roots.dshHome, canonical)) return 'DSH_HOME path ' + canonical
  if (CRITICAL_POSIX.some((root) => isWithin(root, canonical))) return 'system path ' + canonical
  if (CRITICAL_WIN_RE.test(canonical)) return 'system path ' + canonical
  return undefined
}

/** Private-key or credential-file name anywhere in a command. */
function secretNameReason(command, roots) {
  const words = command.split(/[\s;&|()"'=,]+/)
  for (const word of words) {
    if (word === '') continue
    const canonical = normalizePath(word, roots.workspace, roots.home)
    if (canonical !== undefined && PRIVATE_KEY_RE.test(canonical)) return 'private key or credential file ' + canonical
  }
  for (const embedded of embeddedPaths(command)) {
    const canonical = normalizePath(embedded, roots.workspace, roots.home)
    if (canonical !== undefined && PRIVATE_KEY_RE.test(canonical)) return 'private key or credential file ' + canonical
  }
  return undefined
}

/**
 * Synchronous hard-deny reason for the monotonic tool guard.
 * @param execution - the frozen tool execution ({name, arguments}).
 * @param roots - {workspace, home, dshHome, protectDshHome}.
 */
export function guardReason(execution, roots) {
  if (execution === null || typeof execution !== 'object') return undefined
  const name = String(execution.name || '')
  const args = execution.arguments
  const home = roots.home

  if (FILE_TOOLS.has(name)) {
    const path = pathArgument(args)
    if (path === undefined) return undefined
    const namespace = deviceNamespace(path)
    if (namespace !== undefined) return 'mutation targets ' + namespace
    return targetReason(path, roots)
  }
  if (!SHELL_TOOLS.has(name)) return undefined
  const command = args !== null && typeof args === 'object' && typeof args.command === 'string' ? args.command : ''
  if (command === '') return undefined
  if (PRIVILEGE_RE.test(command)) return 'privilege escalation is not permitted'
  if (OS_DAMAGE_RE.test(command)) return 'device or operating-system damage command is not permitted'
  if (NETWORK_RE.test(command) && EXFIL_RE.test(command)) return 'credential or private-data exfiltration pattern is not permitted'
  const secret = secretNameReason(command, roots)
  if (secret !== undefined) return secret
  const analysis = analyzeCommand(command, { cwd: roots.workspace, home: home })
  if (analysis.opaque) return undefined
  for (const write of analysis.writes || []) {
    const resolved = normalizePath(write.raw, write.cwd === undefined ? roots.workspace : write.cwd, home)
    if (resolved === undefined) continue
    const reason = targetReason(resolved, roots)
    if (reason !== undefined) return reason
  }
  return undefined
}
