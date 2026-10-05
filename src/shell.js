// SPDX-License-Identifier: MIT
// Self-contained static command decomposition.
//
// Scope is deliberately narrow: answer "is every provable write target inside a
// trusted root?", and answer "opaque" whenever that cannot be established. This
// is not a shell interpreter, it copies no auto-mode parser code, and it is
// meant to be far smaller than auto-mode's shell.ts while staying fail-closed.
const BACKTICK = String.fromCharCode(96)

/**
 * Split a command line into segments without executing anything.
 * @returns {{opaque: true, reason: string} | {opaque: false, segments: Array}}
 */
export function decompose(source) {
  if (typeof source !== 'string' || source.trim() === '') return { opaque: true, reason: 'empty-command' }
  const text = source
  if (text.indexOf(BACKTICK) >= 0) return { opaque: true, reason: 'backtick-substitution' }
  if (/\$\(|\$\{|<\(|>\(|<<</.test(text)) return { opaque: true, reason: 'command-substitution' }
  if (text.indexOf('<<') >= 0) return { opaque: true, reason: 'heredoc' }
  if (text.indexOf(String.fromCharCode(0)) >= 0) return { opaque: true, reason: 'nul-byte' }

  const segments = []
  let words = []
  let redirects = []
  let buffer = ''
  let started = false
  let quoted = false
  let quote = null
  let failure = null

  const flushWord = () => {
    if (started) {
      words.push({ text: buffer, quoted: quoted })
      buffer = ''
      started = false
      quoted = false
    }
  }
  const endSegment = (op) => {
    flushWord()
    if (words.length > 0 || redirects.length > 0) segments.push({ words: words, redirects: redirects, op: op })
    words = []
    redirects = []
  }
  const readToken = (index) => {
    let out = ''
    let open = null
    let i = index
    if (text[i] === '&') {
      i++
      while (i < text.length && /[0-9-]/.test(text[i])) { out = out + text[i]; i++ }
      return { text: '&' + out, next: i }
    }
    while (i < text.length) {
      const c = text[i]
      if (open !== null) {
        if (c === open) { open = null; i++; continue }
        out = out + c
        i++
        continue
      }
      if (c === '"' || c === "'") { open = c; i++; continue }
      if (c === '\\') { out = out + (text[i + 1] === undefined ? '' : text[i + 1]); i += 2; continue }
      if (c === '$' || c === BACKTICK) { failure = 'expansion-in-redirect'; return { text: out, next: i } }
      if (c === ' ' || c === '\t' || c === '\n' || c === ';' || c === '&' || c === '|' || c === '>' || c === '<') break
      out = out + c
      i++
    }
    return { text: out, next: i }
  }

  let i = 0
  while (i < text.length && failure === null) {
    const ch = text[i]
    if (quote === "'") {
      if (ch === "'") quote = null
      else buffer = buffer + ch
      i++
      continue
    }
    if (quote === '"') {
      if (ch === '"') { quote = null; i++; continue }
      if (ch === '\\') {
        const next = text[i + 1]
        if (next === '"' || next === '\\' || next === '$' || next === BACKTICK) { buffer = buffer + next; i += 2; continue }
        buffer = buffer + ch
        i++
        continue
      }
      if (ch === '$' || ch === BACKTICK) { failure = 'expansion'; break }
      buffer = buffer + ch
      i++
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; quoted = true; started = true; i++; continue }
    if (ch === '\\') { buffer = buffer + (text[i + 1] === undefined ? '' : text[i + 1]); started = true; i += 2; continue }
    if (ch === '$' || ch === BACKTICK) { failure = 'expansion'; break }
    if (ch === ' ' || ch === '\t' || ch === '\r') { flushWord(); i++; continue }
    if (ch === '\n' || ch === ';' || ch === '&' || ch === '|') {
      let op = ch
      if ((ch === '&' || ch === '|') && text[i + 1] === ch) { op = op + ch; i++ }
      endSegment(op)
      i++
      continue
    }
    if (ch === '>') {
      if (started && /^[0-9]+$/.test(buffer)) { buffer = ''; started = false; quoted = false } else flushWord()
      let append = false
      if (text[i + 1] === '>') { append = true; i++ }
      i++
      while (text[i] === ' ' || text[i] === '\t') i++
      const token = readToken(i)
      i = token.next
      if (failure !== null) break
      if (token.text === '') { failure = 'empty-redirect-target'; break }
      if (token.text.charAt(0) !== '&') redirects.push({ target: token.text, append: append })
      continue
    }
    if (ch === '<') {
      flushWord()
      i++
      while (text[i] === ' ' || text[i] === '\t') i++
      const token = readToken(i)
      i = token.next
      if (failure !== null) break
      continue
    }
    buffer = buffer + ch
    started = true
    i++
  }

  if (failure !== null) return { opaque: true, reason: failure }
  if (quote !== null) return { opaque: true, reason: 'unbalanced-quote' }
  endSegment(null)
  return { opaque: false, segments: segments }
}

// ---------------------------------------------------------------------------
// Extraction pass.
//
// decompose() answers "can this be split" and answers opaque for every
// expansion. decomposeWithExtraction() leaves decompose() untouched and adds a
// fail-closed pre-pass in front of it:
//
//   1. scan the source once and build a *placeholder mapping table* -- an array
//      of {start, end, token, kind, payload} records, never an in-place edit;
//   2. apply the table back-to-front, so no index ever shifts while splicing;
//   3. hand the resulting skeleton to the untouched decompose().
//
// Anything the scanner does not fully understand (backticks, process
// substitution, herestrings, an unterminated heredoc, a nested substitution, a
// construct glued to a word) returns opaque. The pass can only ever turn some
// opaque commands into provable ones; it never weakens an existing verdict.
const NUL = String.fromCharCode(0)
// SOH: a byte no accepted shell word can contain, and not the NUL byte that
// decompose() itself rejects, so placeholders survive the second pass.
const MARK = String.fromCharCode(1)
const MAX_EXTRACTION_DEPTH = 3
const MARK_RE = new RegExp(MARK)
const PLACEHOLDER_RE = new RegExp('^' + MARK + '([HSE][0-9]+)' + MARK + '$')
const DELIMITER_RE = /[A-Za-z0-9_]/
const PARAM_EXPANSION_RE = /^[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?$/
// A substitution body we refuse to re-parse: any further expansion, heredoc or
// process substitution inside it stays opaque.
const UNSAFE_SUBSTITUTION_RE = /\$\(|\$\{|<<|<\(|>\(/
const KINDS = { H: 'heredoc', S: 'substitution', E: 'expansion' }

/** True when a word still carries a placeholder marker (whole or glued). */
export function isPlaceholder(text) {
  return typeof text === 'string' && MARK_RE.test(text)
}

/** {kind, index} for a standalone placeholder word, otherwise null. */
export function parsePlaceholder(text) {
  if (typeof text !== 'string') return null
  const match = PLACEHOLDER_RE.exec(text)
  if (match === null) return null
  return { kind: KINDS[match[1].charAt(0)], index: Number(match[1].slice(1)) }
}

function isBoundary(ch) {
  if (ch === undefined || ch === '') return true
  return ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === ';' || ch === '&' ||
    ch === '|' || ch === '<' || ch === '>' || ch === '(' || ch === ')' || ch === '"' || ch === "'"
}

/**
 * Build the placeholder mapping table for every extractable construct.
 * @returns {{opaque: true, reason: string} | {opaque: false, replacements: Array, heredocs: Array, substitutions: Array, expansions: Array}}
 */
function scanExtractions(source) {
  const len = source.length
  const replacements = []
  const consumed = []
  const heredocs = []
  const substitutions = []
  const expansions = []
  let bodyCursor = 0
  let depth = 0
  let quote = null
  let i = 0

  const opaque = (reason) => ({ opaque: true, reason: reason })

  /** Skip a heredoc body we already consumed; its text is data, not commands. */
  const skipConsumed = () => {
    for (let k = 0; k < consumed.length; k++) {
      if (i >= consumed[k][0] && i < consumed[k][1]) { i = consumed[k][1]; return true }
    }
    return false
  }

  const register = (list, letter, payload, start, end) => {
    const token = MARK + letter + list.length + MARK
    list.push(payload)
    replacements.push({ start: start, end: end, token: token, kind: KINDS[letter], payload: payload, text: ' ' + token + ' ' })
    return token
  }

  const liftHeredoc = (start) => {
    let j = start + 2
    let strip = false
    if (source.charAt(j) === '-') { strip = true; j++ }
    else if (source.charAt(j) === '~') return opaque('heredoc-tab-stripping')
    let delimiter = ''
    const wrap = source.charAt(j)
    const quoted = wrap === "'" || wrap === '"'
    if (quoted) j++
    while (j < len && DELIMITER_RE.test(source.charAt(j))) { delimiter += source.charAt(j); j++ }
    if (delimiter === '') return opaque('heredoc-delimiter')
    if (quoted) {
      if (source.charAt(j) !== wrap) return opaque('heredoc-delimiter')
      j++
    } else if (source.charAt(j) === "'" || source.charAt(j) === '"' || DELIMITER_RE.test(source.charAt(j))) {
      return opaque('heredoc-delimiter')
    }
    const newline = source.indexOf('\n', j)
    if (newline < 0) return opaque('heredoc-body')
    // Bodies are consumed in operator order, exactly like the shell reads them.
    const bodyStart = newline + 1 > bodyCursor ? newline + 1 : bodyCursor
    let cursor = bodyStart
    let bodyEnd = -1
    while (cursor <= len) {
      const at = source.indexOf('\n', cursor)
      const lineEnd = at < 0 ? len : at
      const line = source.slice(cursor, lineEnd)
      // Only the <<- form tolerates leading tabs; anything looser could stop
      // early and leave the rest of the body to be read as command text.
      const candidate = strip ? line.replace(/^\t+/, '') : line
      if (candidate === delimiter) { bodyEnd = at < 0 ? len : at + 1; break }
      if (at < 0) break
      cursor = at + 1
    }
    if (bodyEnd < 0) return opaque('heredoc-unterminated')
    const body = source.slice(bodyStart, bodyEnd)
    const payload = {
      delimiter: delimiter,
      quoted: quoted,
      strip: strip,
      // A quoted body is literal; an unquoted one that still carries a command
      // substitution is extracted but never provable.
      expanded: !quoted && (body.indexOf('$(') >= 0 || body.indexOf(BACKTICK) >= 0),
      body: stripTrailingTerminator(body, delimiter)
    }
    const token = register(heredocs, 'H', payload, start, j)
    // The operator becomes the token; the body itself is deleted, so the rest of
    // the operator line (a pipe, a redirect, further heredocs) stays readable.
    replacements.push({ start: bodyStart, end: bodyEnd, token: token, kind: 'heredoc-body', payload: payload, text: '' })
    consumed.push([bodyStart, bodyEnd])
    bodyCursor = bodyEnd
    return { opaque: false, end: j }
  }

  const liftSubstitution = (start) => {
    depth++
    if (depth > MAX_EXTRACTION_DEPTH) return opaque('nesting-too-deep')
    let j = start + 2
    let nesting = 1
    let inner = null
    let innerQuote = null
    while (j < len) {
      const ch = source.charAt(j)
      if (innerQuote === "'") { if (ch === "'") innerQuote = null; j++; continue }
      if (innerQuote === '"') {
        if (ch === '\\') { j += 2; continue }
        if (ch === '"') { innerQuote = null; j++; continue }
        j++
        continue
      }
      if (ch === '\\') { j += 2; continue }
      if (ch === "'" || ch === '"') { innerQuote = ch; j++; continue }
      if (ch === '(') { nesting++; j++; continue }
      if (ch === ')') {
        nesting--
        if (nesting === 0) { inner = source.slice(start + 2, j); j++; break }
        j++
        continue
      }
      j++
    }
    if (inner === null) return opaque('unbalanced-substitution')
    if (UNSAFE_SUBSTITUTION_RE.test(inner)) return opaque('nested-substitution')
    if (!isBoundary(source.charAt(start - 1)) || !isBoundary(source.charAt(j))) return opaque('glued-substitution')
    register(substitutions, 'S', { command: inner, depth: depth }, start, j)
    depth--
    return { opaque: false, end: j }
  }

  const liftExpansion = (start) => {
    depth++
    if (depth > MAX_EXTRACTION_DEPTH) return opaque('nesting-too-deep')
    const close = source.indexOf('}', start + 2)
    if (close < 0) return opaque('unbalanced-expansion')
    const inner = source.slice(start + 2, close)
    if (!PARAM_EXPANSION_RE.test(inner)) return opaque('unsupported-expansion')
    if (!isBoundary(source.charAt(start - 1)) || !isBoundary(source.charAt(close + 1))) return opaque('glued-expansion')
    register(expansions, 'E', { name: inner, text: source.slice(start, close + 1) }, start, close + 1)
    depth--
    return { opaque: false, end: close + 1 }
  }

  while (i < len) {
    if (skipConsumed()) continue
    const ch = source.charAt(i)

    if (quote === "'") {
      if (ch === "'") quote = null
      i++
      continue
    }
    if (quote === '"') {
      if (ch === '\\') { i += 2; continue }
      if (ch === '"') { quote = null; i++; continue }
      if (ch === BACKTICK) return opaque('backtick-substitution')
      if (ch === '$' && (source.charAt(i + 1) === '(' || source.charAt(i + 1) === '{')) {
        const lifted = source.charAt(i + 1) === '(' ? liftSubstitution(i) : liftExpansion(i)
        if (lifted.opaque) return lifted
        i = lifted.end
        continue
      }
      if ((ch === '<' || ch === '>') && source.charAt(i + 1) === '(') return opaque('process-substitution')
      if (ch === '<' && source.charAt(i + 1) === '<') return opaque('heredoc-in-double-quote')
      i++
      continue
    }

    if (ch === '\\') { i += 2; continue }
    if (ch === "'" || ch === '"') { quote = ch; i++; continue }
    if (ch === BACKTICK) return opaque('backtick-substitution')
    if (ch === '$' && source.charAt(i + 1) === '(') {
      const lifted = liftSubstitution(i)
      if (lifted.opaque) return lifted
      i = lifted.end
      continue
    }
    if (ch === '$' && source.charAt(i + 1) === '{') {
      const lifted = liftExpansion(i)
      if (lifted.opaque) return lifted
      i = lifted.end
      continue
    }
    if (ch === '<' && source.charAt(i + 1) === '<') {
      if (source.charAt(i + 2) === '<') return opaque('herestring')
      const lifted = liftHeredoc(i)
      if (lifted.opaque) return lifted
      i = lifted.end
      continue
    }
    if ((ch === '<' || ch === '>') && source.charAt(i + 1) === '(') return opaque('process-substitution')
    i++
  }
  if (quote !== null) return opaque('unbalanced-quote')

  replacements.sort((a, b) => a.start - b.start)
  for (let k = 1; k < replacements.length; k++) {
    if (replacements[k].start < replacements[k - 1].end) return opaque('overlapping-extraction')
  }
  return { opaque: false, replacements: replacements, heredocs: heredocs, substitutions: substitutions, expansions: expansions }
}

/** Drop the terminator line a heredoc body scan already matched. */
function stripTrailingTerminator(body, delimiter) {
  const trimmed = body.endsWith('\n') ? body.slice(0, body.length - 1) : body
  if (trimmed === delimiter) return ''
  if (trimmed.endsWith('\n' + delimiter)) return trimmed.slice(0, trimmed.length - delimiter.length - 1)
  return body
}

/**
 * decompose() plus a fail-closed extraction pre-pass.
 *
 * @param {string} source
 * @returns {{opaque: true, reason: string, extraction?: object} |
 *           {opaque: false, segments: Array, skeleton: string, extraction: {heredocs: Array, substitutions: Array, expansions: Array}}}
 */
export function decomposeWithExtraction(source) {
  if (typeof source !== 'string' || source.trim() === '') return { opaque: true, reason: 'empty-command' }
  if (source.indexOf(NUL) >= 0) return { opaque: true, reason: 'nul-byte' }
  // A marker already in the source would let a real word impersonate a token.
  if (MARK_RE.test(source)) return { opaque: true, reason: 'placeholder-collision' }
  if (source.indexOf(BACKTICK) >= 0) return { opaque: true, reason: 'backtick-substitution' }

  const scanned = scanExtractions(source)
  if (scanned.opaque) return { opaque: true, reason: scanned.reason }
  const extraction = { heredocs: scanned.heredocs, substitutions: scanned.substitutions, expansions: scanned.expansions }

  // Back-to-front splicing: every offset to the left is still valid.
  let skeleton = source
  for (let k = scanned.replacements.length - 1; k >= 0; k--) {
    const replacement = scanned.replacements[k]
    skeleton = skeleton.slice(0, replacement.start) + replacement.text + skeleton.slice(replacement.end)
  }

  const decomposition = decompose(skeleton)
  if (decomposition.opaque) return { opaque: true, reason: decomposition.reason, extraction: extraction }
  for (const segment of decomposition.segments) {
    for (const redirect of segment.redirects) {
      if (isPlaceholder(redirect.target)) return { opaque: true, reason: 'substitution-in-redirect', extraction: extraction }
    }
    for (const word of segment.words) {
      if (isPlaceholder(word.text) && parsePlaceholder(word.text) === null) return { opaque: true, reason: 'glued-placeholder', extraction: extraction }
    }
  }
  // The body of an unquoted heredoc that still contains a command substitution is
  // data whose runtime value we cannot see: extracted for the record, never
  // provable.
  for (const entry of scanned.heredocs) {
    if (entry.expanded) return { opaque: true, reason: 'heredoc-expanded', extraction: extraction }
  }
  return { opaque: false, segments: decomposition.segments, skeleton: skeleton, extraction: extraction }
}
