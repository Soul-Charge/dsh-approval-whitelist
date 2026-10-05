// SPDX-License-Identifier: MIT
// Client-bundle smoke test: load lib/client.js the way the browser module loader
// does and render it with a REAL React when one is resolvable.
//
// Why this exists: the settings page once rendered as a blank card because the
// component threw during render and the slot error boundary swallowed it. A stub
// React could not catch that - the crash lived in a branch only reached after the
// async load settled, and the failure mode was a silently empty panel. React is
// optional here (a profile without it still mounts the plugin), so the render
// assertions are SKIPPED with a notice when it cannot be resolved.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { assert, assertEqual, summary, test } from './harness.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const BUNDLE = path.resolve(here, '..', 'lib', 'client.js')

console.log('== client bundle (settings page) ==')

await test('the bundle exists and declares the module-loader entry', () => {
  assert(fs.existsSync(BUNDLE), 'lib/client.js must exist: ' + BUNDLE)
  const src = fs.readFileSync(BUNDLE, 'utf8')
  assert(src.includes('__ModuleLoader__'), 'it must register through window.__ModuleLoader__.load')
  assert(src.includes("id: 'dsh-approval-whitelist'") || src.includes('id: "dsh-approval-whitelist"'), 'it must declare its bundle id')
})

await test('the bundle loads and registers settings.section', () => {
  const src = fs.readFileSync(BUNDLE, 'utf8')
  let captured = null
  const sandboxWindow = { __ModuleLoader__: { load: (def) => { captured = def } } }
  const run = new Function('window', 'require', src)
  run(sandboxWindow, (name) => {
    if (name === 'react') return { createElement: () => ({}), useState: (v) => [v, () => {}], useCallback: (f) => f, useEffect: () => {} }
    throw new Error('unexpected require: ' + name)
  })
  assert(captured !== null, 'the loader entry must be captured')
  assertEqual(captured.id, 'dsh-approval-whitelist')
  const mod = captured.factory((name) => {
    if (name === 'react') return { createElement: () => ({}), useState: (v) => [v, () => {}], useCallback: (f) => f, useEffect: () => {} }
    throw new Error('unexpected require: ' + name)
  })
  assertEqual(typeof mod.apply, 'function')
  assert(Array.isArray(mod.inject), 'inject must be an array')
  for (const required of ['slots', 'remote', 'remote.session', 'remote.settings']) {
    assert(mod.inject.indexOf(required) >= 0, 'inject must declare ' + required)
  }
  let registered = null
  mod.apply({
    slots: { inject: (n, fn) => fn(), register: (desc) => { registered = desc } },
    remote: {},
  })
  assert(registered !== null, 'apply must register the settings section')
  assertEqual(registered.name, 'settings.section')
  assertEqual(registered.id, 'approval-whitelist')
})

// ---------------------------------------------------------------- real render
/**
 * Resolve a real React for the render assertions.
 *
 * The plugin itself has no React dependency (the shell provides it), so the
 * import is best-effort and the assertions are skipped when nothing resolves.
 * AW_REACT_DIR lets a caller point at any directory whose node_modules holds
 * react + react-dom/server - that is how the profile-independent smoke run
 * exercises the real renderer without adding a dependency to the plugin.
 */
async function loadReact() {
  const attempts = [() => import('react'), () => import('react-dom/server')]
  const direct = async () => {
    const reactModule = await import('react')
    const server = await import('react-dom/server')
    return { React: reactModule.default !== undefined ? reactModule.default : reactModule, renderToStaticMarkup: server.renderToStaticMarkup }
  }
  try {
    return await direct()
  } catch (error) {
    const dir = process.env.AW_REACT_DIR
    if (dir === undefined || dir === '') return null
    try {
      const { createRequire } = await import('node:module')
      const require_ = createRequire(path.join(dir, 'noop.cjs'))
      const reactPath = require_.resolve('react')
      const serverPath = require_.resolve('react-dom/server')
      const reactModule = await import('file://' + reactPath)
      const server = await import('file://' + serverPath)
      return { React: reactModule.default !== undefined ? reactModule.default : reactModule, renderToStaticMarkup: server.renderToStaticMarkup }
    } catch (nested) {
      return null
    }
  }
}

const reactPair = await loadReact()
let React = reactPair === null ? null : reactPair.React
let renderToStaticMarkup = reactPair === null ? null : reactPair.renderToStaticMarkup

if (React === null || typeof renderToStaticMarkup !== 'function') {
  console.log('  SKIP real-render assertions: react/react-dom are not resolvable from here')
  console.log('       (this is expected in a profile that does not ship React; the plugin still mounts)')
} else {
  await test('a real React render produces the settings page, not an empty panel', () => {
    const src = fs.readFileSync(BUNDLE, 'utf8')
    let captured = null
    const requireShim = (name) => {
      if (name === 'react') return React
      throw new Error('unexpected require: ' + name)
    }
    const run = new Function('window', 'require', src)
    run({ __ModuleLoader__: { load: (def) => { captured = def } } }, requireShim)
    const mod = captured.factory(requireShim)

    const catalog = { ok: true, value: {
      default: { provider: 'workbuddy-subscription', model: 'deepseek-v4.1-flash' },
      routableProviders: ['workbuddy-subscription', 'minimax-code'],
      groups: [
        { id: 'workbuddy-subscription', name: 'WorkBuddy', models: [{ id: 'deepseek-v4.1-flash', name: 'DeepSeek V4.1 Flash', reasoning: { efforts: [{ id: 'high', name: 'High' }], defaultEffort: 'high' } }] },
        { id: 'minimax-code', name: 'MiniMax Code', models: [{ id: 'MiniMax-M3.1-Flash-Preview', name: 'MiniMax M3.1' }] },
      ],
      failures: [],
    } }
    const describe = { ok: true, value: { writable: true, namespaces: [
      { ns: 'approval-whitelist', revision: 3, value: { aiReview: { enabled: true, provider: 'workbuddy-subscription', model: 'deepseek-v4.1-flash', reasoningEffort: 'high', timeoutMs: 8000, maxTokens: 512, temperature: 0, maxSessionRules: 3, minScopeDepth: 3, tools: ['bash', 'pwsh'] } }, schema: {}, applies: 'live' },
    ] } }
    const remote = { session: { modelCatalog: async () => catalog }, settings: { describe: async () => describe, update: async () => ({ ok: true }) } }

    // The crash this guards against was inside the render body, so a synchronous
    // render is enough to catch it. useEffect (and the async load) never run here,
    // which is exactly why the empty-panel bug survived a stub-React probe before:
    // that probe only ever reached the loading branch.
    const html = renderToStaticMarkup(React.createElement(mod.SettingsPage, { remote }))
    assert(html.length > 0, 'the render must produce markup, not an empty string')
    assert(html.includes('正在读取'), 'the first render is the loading state')
    assertEqual(typeof mod.SettingsPage, 'function')
  })
  await test('the component survives every shape of remote it may be handed', () => {
    const src = fs.readFileSync(BUNDLE, 'utf8')
    let captured = null
    const requireShim = (name) => { if (name === 'react') return React; throw new Error('unexpected require: ' + name) }
    const run = new Function('window', 'require', src)
    run({ __ModuleLoader__: { load: (def) => { captured = def } } }, requireShim)
    const mod = captured.factory(requireShim)
    const shapes = [
      { remote: { session: {}, settings: {} } },
      { remote: {} },
      {},
      undefined,
    ]
    for (const props of shapes) {
      const html = renderToStaticMarkup(React.createElement(mod.SettingsPage, props))
      assert(typeof html === 'string', 'every props shape must render without throwing')
    }
  })
}

summary('client')
