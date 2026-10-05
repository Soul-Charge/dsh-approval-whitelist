// SPDX-License-Identifier: MIT
// Decide which paths a call will WRITE and which programs it runs.
//
// Read sources are deliberately not write targets: the spike report (section 4.6)
// showed that "any path mentioned" makes 'cp <trusted>/x /etc/cron.d/evil' a
// silent sandbox escape. Only provable write effects count.
import { decompose, decomposeWithExtraction, isPlaceholder, parsePlaceholder } from './shell.js'

const DESTRUCTIVE_RE = /(?:^|[\s;&|()"'])(?:rm|rmdir|unlink|shred|srm|mv|wipefs|fdisk|parted|diskpart|shutdown|reboot|kill|pkill|killall|format)(?:\s|$)|(?:^|[\s;&|()"'])mkfs(?:\.[a-z0-9]+)?(?:\s|$)|(?:^|\s)-delete(?:\s|$)|(?:^|\s)-exec(?:\s|$)/

// Opaque reasons decomposeWithExtraction() is allowed to retry. Every other
// reason (backtick, nul byte, unbalanced quote, tokenizer failure) keeps the
// command opaque exactly as before, and a retry that stays opaque stays opaque.
const EXTRACTABLE_REASONS = new Set(['heredoc', 'command-substitution', 'expansion'])
const MAX_SUBSTITUTION_DEPTH = 3

const READ_VERBS = new Set([
  'cd', 'pwd', 'echo', 'printf', 'cat', 'ls', 'head', 'tail', 'grep', 'rg', 'ag', 'wc', 'sort', 'uniq',
  'diff', 'cmp', 'test', 'true', 'false', 'sleep', 'date', 'which', 'type', 'basename', 'dirname',
  'realpath', 'readlink', 'stat', 'file', 'tree', 'env', 'export', 'set', 'unset', 'source', 'id', 'whoami',
  'find', 'xargs', 'column', 'cut', 'tr', 'sed', 'awk', 'jq', 'sha256sum', 'md5sum', 'git',
])
const COPY_VERBS = new Set(['cp', 'install', 'rsync', 'scp'])
const ALL_TARGET_VERBS = new Set(['tee', 'touch', 'mkdir', 'ln'])
const LAST_TARGET_VERBS = new Set(['truncate', 'chmod', 'chown'])
const PROGRAM_VERBS = new Set([
  'python', 'python3', 'py', 'node', 'nodejs', 'deno', 'bun', 'bunx', 'npx', 'npm', 'pnpm', 'yarn',
  'bash', 'sh', 'zsh', 'dash', 'fish', 'pwsh', 'powershell', 'cmd', 'make', 'cargo', 'rustc', 'go',
  'java', 'javac', 'dotnet', 'ruby', 'php', 'perl', 'lua', 'Rscript', 'tsc', 'tar', 'unzip', 'zip',
  'gzip', 'gunzip', 'bzip2', 'xz', '7z', 'docker', 'podman', 'systemctl', 'service', 'pip', 'pip3',
  'uv', 'poetry', 'conda', 'pytest', 'tox', 'ffmpeg', 'pandoc', 'convert', 'magick', 'curl', 'wget',
  'ssh', 'scp', 'sftp', 'rsync', 'nc', 'ncat', 'telnet', 'apt', 'apt-get', 'dpkg', 'dnf', 'yum', 'pacman', 'vim', 'vi', 'nano',
])

const GIT_WRITE = new Set(['add', 'commit', 'init', 'tag', 'branch', 'merge', 'rebase', 'apply', 'am'])
const GIT_READ = new Set(['status', 'diff', 'log', 'show', 'rev-parse', 'ls-files', 'ls-tree', 'describe', 'blame', 'grep', 'cat-file', 'config', 'remote', 'shortlog', 'whatchanged', 'count-objects', 'version', 'symbolic-ref'])
const GIT_NETWORK = new Set(['push', 'pull', 'fetch', 'clone', 'submodule', 'lfs'])
const GIT_DESTRUCTIVE = new Set(['reset', 'clean', 'checkout', 'restore', 'rm', 'mv', 'stash', 'switch', 'prune', 'gc'])

const GIT_VALUE_FLAGS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env'])
/** Interpreters whose inline-code flag hides arbitrary behaviour in an operand. */
const INTERPRETER_VERBS = new Set(['python', 'python3', 'py', 'node', 'nodejs', 'deno', 'bun', 'bash', 'sh', 'zsh', 'dash', 'fish', 'pwsh', 'powershell', 'perl', 'ruby', 'php', 'lua', 'Rscript'])
const CODE_FLAGS = new Set(['-c', '-e', '--eval', '-p', '--print', '-pe', '-E'])
const SED_VALUE_FLAGS = new Set(['-e', '--expression', '-f', '--file'])

function basenameOf(value) {
  const normalized = value.replaceAll('\\', '/')
  const cut = normalized.lastIndexOf('/')
  return cut >= 0 ? normalized.slice(cut + 1) : normalized
}

function isFlag(word) {
  return word.length > 1 && word.charAt(0) === '-'
}

function isGlob(word) {
  return /[*?[]/.test(word)
}

function isNullSink(word) {
  return /^\/dev\/(?:null|stdout|stderr|fd\/[0-9]+)$/.test(word) || /^(?:nul|NUL)$/.test(word)
}

/**
 * Absolute-path-looking tokens embedded in arbitrary text (inline code). The
 * lookbehind keeps a relative tail such as "tests/conftest.py" from being read
 * as the absolute "/conftest.py".
 */
export function embeddedPaths(text) {
  const found = []
  const posix = /(?<![\w.\/])\/[A-Za-z0-9._@+-]+(?:\/[A-Za-z0-9._@+-]+)*/g
  const windows = /(?<![\w:])([A-Za-z]:\\[^\s"'|;&<>()]*)/g
  let match = posix.exec(text)
  while (match !== null) { found.push(match[0]); match = posix.exec(text) }
  match = windows.exec(text)
  while (match !== null) { found.push(match[0]); match = windows.exec(text) }
  return found
}

function push(list, raw, cwd) {
  list.push({ raw: raw, cwd: cwd, glob: isGlob(raw) })
}

/**
 * A heredoc body is data or embedded code, never a command of its own, so it is
 * never treated as one. Its absolute paths are surfaced instead: as unprovable
 * write targets the rule layer has to judge, and -- for a program fed by the body
 * -- as inline code, exactly like `python3 -c`.
 */
function surfaceHeredocBodies(segment, bodies, writes, unprovable, cwd) {
  for (const body of bodies) {
    segment.heredocs.push({ delimiter: body.delimiter, quoted: body.quoted, strip: body.strip, expanded: body.expanded })
    if (segment.kind === 'program') segment.inlineCode.push(body.body)
    for (const embedded of embeddedPaths(body.body)) {
      unprovable.push({ raw: embedded, reason: 'path embedded in heredoc body' })
      push(writes, embedded, cwd)
      segment.writes.push(embedded)
    }
  }
}

/** Map placeholder kind -> extracted payloads, for placeholder words to resolve. */
function buildTokenIndex(extraction) {
  const index = new Map()
  if (extraction === null) return index
  index.set('heredoc', extraction.heredocs)
  index.set('substitution', extraction.substitutions)
  index.set('expansion', extraction.expansions)
  return index
}

/**
 * Analyze one command line into write effects and executed programs.
 * @returns {{opaque: boolean, reason?: string, destructive?: boolean, segments?: Array, writes?: Array, hasProgram?: boolean, unprovable?: Array, extraction?: object|null}}
 */
export function analyzeCommand(command, options) {
  const opts = options || {}
  const depth = typeof opts.depth === 'number' ? opts.depth : 0
  if (depth > MAX_SUBSTITUTION_DEPTH) return { opaque: true, reason: 'nesting-too-deep', writes: [], hasProgram: false }

  // Fail-closed: an extraction-capable opaque reason is retried exactly once
  // through decomposeWithExtraction(), which is opaque again for anything it
  // cannot prove. Backticks, NUL bytes, unbalanced quotes and tokenizer
  // failures never reach it.
  let decomposition = decompose(command)
  let extraction = null
  if (decomposition.opaque && EXTRACTABLE_REASONS.has(decomposition.reason)) {
    const attempt = decomposeWithExtraction(command)
    if (attempt.opaque) return { opaque: true, reason: attempt.reason, writes: [], hasProgram: false }
    decomposition = attempt
    extraction = attempt.extraction
  }
  if (decomposition.opaque) return { opaque: true, reason: decomposition.reason, writes: [], hasProgram: false }
  if (DESTRUCTIVE_RE.test(command)) return { opaque: false, destructive: true, reason: 'destructive-verb', segments: [], writes: [], hasProgram: false }

  const segments = []
  const writes = []
  const unprovable = []
  const tokenIndex = buildTokenIndex(extraction)
  let hasProgram = false
  let cwd = opts.cwd

  for (const rawSegment of decomposition.segments) {
    // Extracted regions survive as placeholder words. A placeholder glued to a
    // real word never reaches this point (decomposeWithExtraction refuses it),
    // so every one of them is a whole word and can leave the verb/operand list.
    const lifted = []
    const words = []
    for (const word of rawSegment.words) {
      if (!isPlaceholder(word.text)) { words.push(word.text); continue }
      const hit = parsePlaceholder(word.text)
      if (hit === null) return { opaque: true, reason: 'glued-placeholder', writes: [], hasProgram: false }
      const payloads = tokenIndex.get(hit.kind)
      const payload = payloads === undefined ? undefined : payloads[hit.index]
      if (payload === undefined) return { opaque: true, reason: 'unknown-placeholder', writes: [], hasProgram: false }
      lifted.push({ kind: hit.kind, payload: payload })
    }
    const heredocBodies = lifted.filter((entry) => entry.kind === 'heredoc').map((entry) => entry.payload)
    const substitutions = lifted.filter((entry) => entry.kind === 'substitution').map((entry) => entry.payload)
    const hasExpansion = lifted.some((entry) => entry.kind === 'expansion')

    let start = 0
    while (start < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[start])) start++
    const args = words.slice(start)

    // A $( ) sub-command and a ${ } expansion produce a value nobody can see.
    // Two independent guards keep them fail-closed, and both are needed:
    //   - the verb must be a pure reader, so dropping the unknown operand can
    //     never re-classify a write verb (`cp $(x) /tmp/b` would otherwise look
    //     like a one-operand read);
    //   - and the segment must still classify as a read once every redirect has
    //     been folded in, so `echo $(x) > f`, `sed -i ... $(x) f` and
    //     `git commit -m $(msg)` all stay opaque exactly as before.
    if (substitutions.length > 0 || hasExpansion) {
      if (args.length === 0 || !READ_VERBS.has(basenameOf(args[0]))) {
        return { opaque: true, reason: 'unproven-substitution-position', writes: [], hasProgram: false }
      }
    }

    const globals = []
    for (const redirect of rawSegment.redirects) {
      if (!isNullSink(redirect.target)) globals.push(redirect.target)
    }

    if (args.length === 0) {
      for (const target of globals) push(writes, target, cwd)
      const bare = { kind: 'write', verb: null, writes: globals.slice(), cwd: cwd, unprovable: false, heredocs: [], substitutions: [] }
      surfaceHeredocBodies(bare, heredocBodies, writes, unprovable, cwd)
      segments.push(bare)
      continue
    }

    const verb = basenameOf(args[0])
    const operands = args.slice(1).filter((word) => !isFlag(word))
    const segment = { kind: 'read', verb: verb, writes: [], cwd: cwd, unprovable: false, operands: args.slice(1), inlineCode: [], heredocs: [], substitutions: [] }
    if (INTERPRETER_VERBS.has(verb)) {
      for (let i = 1; i < args.length; i++) {
        const word = args[i]
        if (word.startsWith('--eval=')) { segment.inlineCode.push(word.slice(7)); continue }
        if (CODE_FLAGS.has(word) && args[i + 1] !== undefined) { segment.inlineCode.push(args[i + 1]); i++ }
      }
    }

    if (verb === 'cd') {
      const next = operands[0]
      if (next === undefined || next === '-' || next === '~') cwd = next === undefined ? opts.home : opts.home
      else cwd = resolveRaw(next, cwd)
      segment.kind = 'control'
    } else if (verb === 'git') {
      let sub = null
      for (let i = 1; i < args.length; i++) {
        if (GIT_VALUE_FLAGS.has(args[i])) { i++; continue }
        if (args[i] === '-C') { cwd = resolveRaw(args[i + 1], cwd); i++; continue }
        if (isFlag(args[i])) continue
        sub = args[i]
        break
      }
      if (sub === null) segment.kind = 'read'
      else if (GIT_WRITE.has(sub)) { segment.kind = 'program'; hasProgram = true; segment.program = verb; segment.writes = [cwd] }
      else if (GIT_READ.has(sub)) segment.kind = 'read'
      else if (GIT_NETWORK.has(sub)) segment.kind = 'network'
      else if (GIT_DESTRUCTIVE.has(sub)) segment.kind = 'program'
      else { segment.kind = 'program'; hasProgram = true; segment.program = verb }
      // git write effects target the repository the cwd belongs to.
      if (segment.kind === 'program' && segment.writes.length > 0) for (const target of segment.writes) push(writes, target, cwd)
    } else if (COPY_VERBS.has(verb)) {
      const targetFlag = args.indexOf('-t') >= 0 || args.indexOf('--target-directory') >= 0
      let dest = null
      let destDir = null
      for (let i = 1; i < args.length; i++) {
        const word = args[i]
        if (word === '-t' || word === '--target-directory') { destDir = args[i + 1]; i++; continue }
        if (word.startsWith('--target-directory=')) { destDir = word.slice(19); continue }
      }
      if (destDir !== undefined && destDir !== null) dest = destDir
      else if (targetFlag) dest = null
      else if (operands.length >= 2) dest = operands[operands.length - 1]
      if (dest !== null && dest !== undefined && dest !== '') {
        push(writes, dest, cwd)
        segment.writes = [dest]
      }
      segment.kind = segment.writes.length > 0 ? 'write' : 'read'
    } else if (ALL_TARGET_VERBS.has(verb)) {
      for (const operand of operands) { if (operand !== '') { push(writes, operand, cwd); segment.writes.push(operand) } }
      segment.kind = segment.writes.length > 0 ? 'write' : 'read'
    } else if (LAST_TARGET_VERBS.has(verb)) {
      const last = operands[operands.length - 1]
      if (last !== undefined && operands.length > 0) { push(writes, last, cwd); segment.writes.push(last) }
      segment.kind = segment.writes.length > 0 ? 'write' : 'read'
    } else if (verb === 'dd') {
      for (const word of args.slice(1)) {
        if (word.startsWith('of=')) { const value = word.slice(3); if (value !== '') { push(writes, value, cwd); segment.writes.push(value) } }
      }
      segment.kind = segment.writes.length > 0 ? 'write' : 'read'
    } else if (verb === 'sed') {
      const inPlace = args.some((word) => word === '-i' || word.startsWith('-i') || word === '--in-place')
      if (inPlace) {
        const usesScriptFlag = args.some((word) => word === '-e' || word === '--expression' || word === '-f' || word === '--file')
        let skipped = false
        for (let i = 1; i < args.length; i++) {
          const word = args[i]
          if (SED_VALUE_FLAGS.has(word)) { i++; continue }
          if (isFlag(word)) continue
          if (!usesScriptFlag && !skipped) { skipped = true; continue }
          push(writes, word, cwd)
          segment.writes.push(word)
        }
        segment.kind = segment.writes.length > 0 ? 'write' : 'read'
      } else segment.kind = 'read'
    } else if (PROGRAM_VERBS.has(verb)) {
      segment.kind = 'program'
      hasProgram = true
      segment.program = verb
    } else if (READ_VERBS.has(verb)) {
      segment.kind = 'read'
    } else {
      // Unknown verb: an unverifiable program, never a read.
      segment.kind = 'program'
      hasProgram = true
      segment.program = verb
    }

    for (const target of globals) { push(writes, target, cwd); segment.writes.push(target) }
    if (segment.kind === 'read' && segment.writes.length > 0) segment.kind = 'write'

    // A $( ) sub-command and a ${ } expansion both produce a value nobody can
    // see. They are only tolerated in a segment that provably writes nothing of
    // its own: cp/tee/dd/sed -i/git, a redirect into a placeholder, and even a
    // redirected echo all stay opaque, exactly as before.
    if (substitutions.length > 0 || hasExpansion) {
      if (segment.kind !== 'read') return { opaque: true, reason: 'unproven-substitution-position', writes: [], hasProgram: false }
    }

    surfaceHeredocBodies(segment, heredocBodies, writes, unprovable, cwd)

    // A $( ) sub-command is a real command, so its write effects are merged into
    // this analysis rather than dropped -- and it is recorded as its own program
    // segment, otherwise the program it runs would stay invisible to the rule
    // layer, which only looks at segments of kind "program".
    for (const sub of substitutions) {
      const analysis = analyzeCommand(sub.command, { cwd: cwd, home: opts.home, depth: depth + 1 })
      if (analysis.opaque) return { opaque: true, reason: 'opaque-substitution', writes: [], hasProgram: false }
      if (analysis.destructive) return { opaque: false, destructive: true, reason: 'destructive-verb', segments: [], writes: [], hasProgram: false }
      for (const write of analysis.writes) writes.push(write)
      if (analysis.hasProgram) hasProgram = true
      segment.substitutions.push(sub.command)
      segments.push({
        kind: 'program',
        verb: 'substitution',
        program: 'substitution',
        writes: [],
        cwd: cwd,
        unprovable: true,
        operands: [sub.command],
        inlineCode: [sub.command],
        heredocs: [],
        substitutions: [sub.command],
      })
    }

    segments.push(segment)
  }

  return {
    opaque: false,
    destructive: false,
    segments: segments,
    writes: writes,
    hasProgram: hasProgram,
    unprovable: unprovable,
    extraction: extraction === null ? null : {
      heredocs: extraction.heredocs.map((entry) => ({ delimiter: entry.delimiter, quoted: entry.quoted, strip: entry.strip, expanded: entry.expanded })),
      substitutions: extraction.substitutions.map((entry) => entry.command),
      expansions: extraction.expansions.map((entry) => entry.name),
    },
  }
}

/** Resolve one raw operand against a cwd without touching the filesystem. */
function resolveRaw(raw, cwd) {
  if (cwd === undefined) return raw.charAt(0) === '/' ? raw : undefined
  if (raw.charAt(0) === '/') return raw.replace(/\/+$/, '') || '/'
  if (cwd === '/') return '/' + raw
  return (cwd.replace(/\/+$/, '') + '/' + raw).replace(/\/+$/, '')
}
