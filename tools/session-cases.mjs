#!/usr/bin/env node
// Read DSH session logs (optionally multi-frame zstd) and report structure.
// Read-only; prints counts, seq numbers and field NAMES only - never field values.
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'

const ZSTD_MAGIC = 0xfd2fb528

/** Split a concatenated Zstandard stream into independent frame ranges. */
export function scanFrames(buffer) {
  const frames = []
  let offset = 0
  while (offset + 4 <= buffer.length) {
    const start = offset
    if (buffer.readUInt32LE(offset) !== ZSTD_MAGIC) throw new Error('invalid zstd magic at byte ' + offset)
    offset += 4
    if (offset >= buffer.length) return { frames, tornStart: start }
    const descriptor = buffer.readUInt8(offset)
    offset += 1
    if ((descriptor & 24) !== 0) throw new Error('reserved frame-header bit')
    const contentSizeFlag = descriptor >>> 6
    const singleSegment = (descriptor & 32) !== 0
    const checksum = (descriptor & 4) !== 0
    const dictionaryFlag = descriptor & 3
    const dictionaryBytes = dictionaryFlag === 3 ? 4 : dictionaryFlag
    const contentSizeBytes = contentSizeFlag === 0 ? (singleSegment ? 1 : 0) : 1 << contentSizeFlag
    const remainingHeaderBytes = (singleSegment ? 0 : 1) + dictionaryBytes + contentSizeBytes
    if (offset + remainingHeaderBytes > buffer.length) return { frames, tornStart: start }
    offset += remainingHeaderBytes
    for (;;) {
      if (offset + 3 > buffer.length) return { frames, tornStart: start }
      const blockHeader = buffer.readUIntLE(offset, 3)
      offset += 3
      const lastBlock = (blockHeader & 1) !== 0
      const blockType = (blockHeader >>> 1) & 3
      const blockSize = blockHeader >>> 3
      if (blockType === 3) throw new Error('reserved block type')
      const payloadBytes = blockType === 1 ? 1 : blockSize
      if (offset + payloadBytes > buffer.length) return { frames, tornStart: start }
      offset += payloadBytes
      if (lastBlock) break
    }
    if (checksum) {
      if (offset + 4 > buffer.length) return { frames, tornStart: start }
      offset += 4
    }
    frames.push({ start, end: offset })
  }
  return { frames }
}

export function readLog(file) {
  const buffer = fs.readFileSync(file)
  let text
  if (file.endsWith('.zstd')) {
    const { frames } = scanFrames(buffer)
    const parts = frames.map((f) => zlib.zstdDecompressSync(buffer.subarray(f.start, f.end)))
    text = Buffer.concat(parts).toString('utf8')
  } else text = buffer.toString('utf8')
  const events = []
  for (const line of text.split('\n')) {
    const t = line.trim()
    if (!t) continue
    try { events.push(JSON.parse(t)) } catch { /* skip torn line */ }
  }
  return events
}

export function listSessionFiles(root = path.join(process.env.HOME, '.dsh', 'sessions')) {
  const out = []
  for (const proj of fs.readdirSync(root)) {
    const projDir = path.join(root, proj)
    if (!fs.statSync(projDir).isDirectory()) continue
    for (const sess of fs.readdirSync(projDir)) {
      const sessDir = path.join(projDir, sess)
      if (!fs.statSync(sessDir).isDirectory()) continue
      for (const f of fs.readdirSync(sessDir)) {
        if (/^session.*\.jsonl(\.zstd)?$/.test(f)) out.push(path.join(sessDir, f))
      }
    }
  }
  return out.sort()
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  const mode = process.argv[2] ?? '--scan'
  if (mode === '--scan') {
    const rows = []
    for (const file of listSessionFiles()) {
      try {
        const events = readLog(file)
        const asked = events.filter((e) => e.type === 'approval/asked').length
        if (asked > 0) rows.push({ asked, events: events.length, file })
      } catch { /* unreadable */ }
    }
    rows.sort((a, b) => b.asked - a.asked)
    console.log('sessions with approval/asked:', rows.length)
    for (const r of rows.slice(0, 12)) console.log('  asked=' + r.asked + ' events=' + r.events + ' ' + r.file)
  }
  if (mode === '--census') {
    const file = process.argv[3]
    const events = readLog(file)
    const types = {}
    for (const e of events) types[e.type] = (types[e.type] ?? 0) + 1
    console.log('events', events.length)
    console.log(JSON.stringify(types, null, 1))
    for (const t of ['approval/asked', 'tool/call', 'tool/result', 'tool/ptc-dispatch']) {
      const e = events.find((x) => x.type === t)
      if (e) console.log(t, 'keys=', Object.keys(e.data ?? {}).join(','), 'top-level keys=', Object.keys(e).join(','))
    }
    const asked = events.filter((e) => e.type === 'approval/asked')
    console.log('approval seqs:', asked.map((e) => e.seq).join(','))
    console.log('tool/call names:', [...new Set(events.filter((e) => e.type === 'tool/call').map((e) => e.data?.name))].join(','))
  }
}
