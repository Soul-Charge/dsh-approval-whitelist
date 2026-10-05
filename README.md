# dsh-approval-whitelist

An independent DSH plugin that makes **pre-approved trusted-directory writes stop asking**.
It sits on the sandbox escalation approval seam (`approval/request`) and grants a
one-shot `allowed-once` when the call's **write targets are provably inside a
directory the user trusted**.

- Taskbook: `tasks/dsh-approval-whitelist/TASKBOOK.md`
- Design + spike evidence: `tasks/dsh-approval-whitelist/README.md`,
  `projects/dsh-approval-whitelist/spike/REPORT.md`
- **Zero coupling to `dsh-auto-mode`**: nothing from auto-mode is imported and no
  auto-mode event is observed, so deleting auto-mode leaves this working
  (verified by `test/integration.mjs`, which composes no auto-mode at all).

---

## 1. What it does

| # | Registration | Behaviour |
|---|---|---|
| 1 | `tools/pre-execute` `{append:true}` | Registers `callId -> {tool, arguments, session}` in an LRU (500). **Never returns a decision** — short-circuiting here would skip the registration listeners of plugins mounted after us (spike §4.7) without saving a prompt (spike §4.6). |
| 2 | `approval/request` `{prepend:true}` | The **only** place a prompt is actually saved. An escalation is granted once iff (a) its own `callId` is in our table, (b) the reason is structurally a sandbox escalation, and (c) the call's provable write targets are all inside a live trusted rule. |
| 3 | `ctx.tools.guard()` | Self-held monotonic hard deny, so no rule can be used to bypass the hard line. |

Plus `/permit` (registered through the optional `commands` injection) and an append-only
audit log.

## 2. Level semantics (the user's choice per rule)

`/permit add <path> [code|data] [global]` — default `code`, scope `session`.

| Level | What may be auto-approved |
|---|---|
| `code` (default, strictest) | Only **statically provable pure writes**: the `write`/`edit` tool's own target, and shell redirections / `cp`,`install`,`rsync` destinations / `tee` / `touch` / `mkdir` / `sed -i` / `dd of=`. **Executing a program is never allowed** — its behaviour is not provable. |
| `data` (explicit opt-in, higher risk) | Everything `code` allows, **plus running programs** whose every path-like operand (and every absolute path hidden inside inline code such as `python3 -c`) stays inside the rule root or the session workspace. The program's own behaviour is *not* verifiable; declaring a rule as `data` is the user accepting that. |

Identical red lines at both levels:

- deletion / move verbs (`rm`, `rmdir`, `mv`, `shred`, `find -delete`, `mkfs`, …) → never
- opaque syntax (command substitution, backticks, heredoc, `$VAR`, unbalanced quotes) → never
- any provable write target outside the rule root → never
- glob write targets → never
- a symlinked path component on the way to the target → never
- device / NT namespaces, filesystem roots, the user-home root, credential stores,
  private keys, privilege escalation, network exfiltration → denied by the guard
  *before* the whitelist is even consulted

## 3. Measured acceptance (real data, not synthetic)

`test/cases.json` holds the **23 real escalation requests** from the myproject session
(`approval/asked` seq 299…1070), extracted from the DSH session log by
`tools/extract-cases.mjs` together with the exact tool arguments and the session cwd.
`test/replay.mjs` feeds them straight into the decision engine:

```
rule root: /home/user/myproject/data/plugins   session cwd: /mnt/d/myproject
code-level allowed: 6/23    data-level allowed: 22/23    false allows: 0
```

- `code` = 6/23: the six `edit` calls whose `file_path` is inside the root. Everything
  else is a program execution and is not provable.
- `data` = 22/23: the six edits, the four `git add/commit` calls, eleven
  `python3 <workspace>/script.py` calls and one mixed `python3 … && python3 -c …` call.
- The single refusal is seq 395, a self-declared probe that writes to
  `/mnt/d/myproject/temp/` (the session workspace, not the trusted root). The workspace
  needs no escalation at all, so a root-scoped rule correctly declines it.
- README §9's acceptance target (`>= 21/23`, 0 false allows) is therefore met — but
  **only at level `data`**, and only because the user explicitly declares the root as
  `data`. Do not read `data` as "the weak setting that is fine to default to": see §5.

Negative coverage (`test/negative.mjs`, 29 assertions) includes the spike's proven hole
(`cp <trusted>/data.json /etc/cron.d/evil` → refused), `ln -s` escapes, heredoc writes,
inline `python3 -c "open('/etc/...','w')"`, glob targets, `~/.dsh` writes without a rule,
private-key reads, `.env` exfiltration, block devices and `sudo`.

## 4. Install

The plugin is meant to live outside the workspace, like the other local plugins:

```bash
# 1. copy the sources to the local plugin directory
cp -r projects/dsh-approval-whitelist /home/user/.dsh/plugins/dsh-approval-whitelist
#    (the inner test/node_modules symlink is only for the test run; drop it in the copy)

# 2. link it into the web profile
cd /home/user/.dsh/profiles/web
PNPM_CONFIG_STORE_DIR=/home/user/.cache/pnpm-store \
  dsh plugin --profile web add link:/home/user/.dsh/plugins/dsh-approval-whitelist

# 3. add "dsh-approval-whitelist" to dsh.profile.bundles, AFTER @nanmicoder/dsh-auto-mode
```

Then in the UI:

```
/permit add /home/user/myproject/data/plugins data global
/permit list
```

Rule store: `~/.dsh/approval-whitelist.json` (atomic replace, 0600).
Audit log: `~/.dsh/approval-whitelist.audit.log`, one JSON line per judgement:

```json
{"ts":...,"callId":...,"ruleId":"r1","level":"data","result":"allowed-once",
 "target":["..."],"commitHash":"<12-hex plugin build fingerprint>",
 "tool":"bash","sessionId":"...","code":"allowed","note":"matched rule r1"}
```

Rule edits on disk are picked up on the next judgement (mtime check), so
`/permit add` / hand edits / `/permit rm` take effect without restarting DSH.

### Configuration

```yaml
- insert:
    - id: approval-whitelist
      name: dsh-approval-whitelist
      config:
        enabled: true
        storePath: ~/.dsh/approval-whitelist.json
        auditPath: ~/.dsh/approval-whitelist.audit.log
        audit: true
        maxCallSites: 500
        guard:
          enabled: true
          protectDshHome: false   # true = auto-mode parity: hard-deny ~/.dsh writes
```

## 5. Honest limits and residual risk

1. **`data` level is a trust declaration, not a proof.** At `data` the plugin grants
   `danger-full-access` for a call that runs a program whose behaviour it cannot see
   (`python3 <script>`, `bash script.sh`, `git commit` hooks, inline `-c`). An agent that
   can write a script into the session workspace can therefore get full access while a
   `data` rule exists. That is exactly why `code` is the default and `data` requires the
   user to type it out.
2. **`allowed-once` only.** Nothing here changes the session permission preset, writes a
   standing policy, or weakens the bwrap sandbox for later calls.
3. **`approval/asked` is still logged and still visible in the UI.** Auto-granting stops
   the *interruption*, not the *record*; session logs cannot distinguish an auto-grant
   from a human click, which is why acceptance is measured by offline replay.
4. **The guard deviates from auto-mode's list on purpose.** auto-mode also hard-denies the
   whole `DSH_HOME` tree; here that is `guard.protectDshHome` and defaults to **false**,
   because this workspace's `~/.dsh/AGENTS.md` has the agent write `~/.dsh` files through
   an approval escalation. Set it to `true` for full auto-mode parity.
5. **Reads are not analysed.** Only writes are judged — the sandbox already allows reads
   everywhere, so allowing a call does not widen read access. The guard still refuses
   private-key/credential *names* anywhere in a command.
6. **Not a security boundary against a hostile agent.** It is a prompt-reduction layer
   whose worst sound failure is "asked one more time" (`code`) — but see (1) for `data`.
7. **"The agent cannot call `/permit`" is a property of the deployment, not of this plugin.**
   The taskbook lists it as a hard constraint. In this profile the model's tool catalog
   contains no tool that can execute commands or define dynamic cordis plugins
   (`cordis_inspect_*` is documented read-only and `dsh-tool-cordis`'s dynamic-plugin
   tools are not composed), so the constraint holds today. It is not enforced *by this
   plugin*: the command handler cannot see whether the caller was a human UI. Two
   mitigations are built in and do not depend on that assumption: every rule mutation is
   written to the audit log (`result: "rule-added"` / `"rule-removed"`), and a rule can
   never unlock a path the guard hard-denies (`/etc`, credentials, devices, …). The only
   gap would be a rule covering `~/.dsh` while `guard.protectDshHome` stays `false`.

## 6. AI approval layer (optional, **off by default**)

When a sandbox escalation is raised and the whitelist refuses it, the plugin can
ask a model you nominate whether the call is safe. The model sees **structured
facts only** (tool name, canonical write targets the static analyser already
proved, the programs that would run, destructive/opaque flags, the session
workspace, the live rule roots) plus the raw command as one quoted, explicitly
untrusted data field. It may answer `allow-once`, `allow-session` or `ask`.

**Everything the model says is a request, not a decision.** `src/ai.js`
(`enforceAiDecision`, `deriveScopeRoot`) decides what actually happens:

| Model said | The server does |
|---|---|
| `ask` | human prompt, exactly as before |
| `allow-once` | one grant for this call, no rule written |
| `allow-session` | one grant, **plus** a rule only if every check below passes |

A session rule requires **all** of: no guard red line, no destructive verb, no
opaque syntax, no program execution (i.e. the call is provable at level `code`),
at least one provable write target, a real session id, a per-session cap not yet
reached, and a scope root that the **server** derives from the proven targets -
rejecting filesystem roots, the home root, anything the guard denies, anything
with a symlinked component, and anything shallower than `minScopeDepth`.
Otherwise `allow-session` is **downgraded to allow-once** and the reason is
recorded in the audit line (`degraded`).

Non-negotiable: an AI-created rule is always `level: code` and `scope: session`.
Neither is configurable, and no answer the model can give changes that.

Fail-closed by construction: no `llm` service, no named route, an unresolvable
route, a timeout, an adapter error, a non-stop finish, empty text, junk text, or a
decision outside the vocabulary all become `ask`. The timeout is enforced by the
plugin itself, not only by the abort signal, so a slow adapter cannot hang an
approval.

```yaml
        aiReview:
          enabled: false            # default; switch on deliberately
          provider: ''              # empty = follow the session's own model
          model: ''                 # empty = follow the session's own model
          reasoningEffort: ''       # empty = follow the session's effort
          timeoutMs: 8000
          maxTokens: 512
          temperature: 0
          tools: [bash, pwsh]        # only these tools are ever put to the model
          maxSessionRules: 3         # AI-created rules per session
          minScopeDepth: 3
```

### Which model reviews

Leaving `provider` and `model` **empty** means *use the model this session is
already running on*: the plugin reads the session's logged request header
(`session.requestHeader().config`), falling back to the agent's own
`options.provider`/`options.model`. Change your model in DSH and the reviewer
follows it with no plugin edit. An explicit `provider`+`model` overrides that and
pins the reviewer to one route. An `aiReview` route that cannot be resolved
(blank config *and* no session route) is **fail-closed**: the request goes to the
human prompt, and no model call is made.

With `enabled: false` (the default) the plugin makes **zero** LLM calls and
behaves exactly as it did before this layer existed.

Residual risk, stated plainly: an `allow-once` from the model grants a real
`danger-full-access` for one call, including for destructive commands - the
session rule is what the hard limits protect, and it is exactly the destructive
and program-execution cases that can never get one. Enabling this layer moves
some decisions from code to a model; keep `enabled: false` unless the prompting
saved is worth that.

## 7. Files

| File | Role |
|---|---|
| `src/index.js` | `apply()`: the three registrations, `/permit`, self-check log |
| `src/rules.js` | config defaults, rule model/CRUD, the decision engine and the two levels |
| `src/targets.js` | self-contained static extraction of write effects and executed programs |
| `src/shell.js` | self-contained shell decomposition (opaque detection, quotes, redirections) |
| `src/paths.js` | path canonicalization, WSL/Windows alias handling, containment, symlink probe |
| `src/guard.js` | the self-held monotonic hard deny |
| `src/ai.js` | optional AI review: facts, prompt, strict parse, scope derivation, the hard safety layer, the fail-closed reviewer |
| `src/store.js` | atomic rule store + audit append (fail-closed) |
| `test/unit.mjs` | 26 assertions on the building blocks |
| `test/negative.mjs` | 29 red-line assertions + positive controls |
| `test/replay.mjs` | the 23 real cases, both levels |
| `test/integration.mjs` | real cordis + dsh-tools + dsh-user-approval, no auto-mode |
| `test/run-all.mjs` | `node test/run-all.mjs` (the `npm test` entry) |
| `test/ai.mjs` | 42 assertions on parsing, scope derivation, the safety constraints and the fail-closed reviewer |
| `test/cases.json` | the extracted real escalation cases (credential-looking strings redacted) |
| `tools/session-cases.mjs` | read DSH session logs (multi-frame zstd) / census them |
| `tools/extract-cases.mjs` | regenerate `test/cases.json` from a session log |
| `tools/verify-live.mjs` | post-install check: installed bytes vs tested source, live rules, replay, backstops, audit |
| `docs/TESTING.md` | testing guide: self-check / suites / real end-to-end acceptance / FAQ |

Run everything with:

```bash
cd projects/dsh-approval-whitelist
node test/run-all.mjs          # 68 assertions across four suites
node tools/verify-live.mjs     # post-install check against the LIVE rule store
```

Test scratch lives in `$TMPDIR/dsh-approval-whitelist-tests` (override with
`AW_TEST_TMP`), **never inside the plugin tree**: the installed copy under
`~/.dsh/plugins` is read-only, and writing scratch next to the test files made the
shipped suite fail from exactly the location users run it. See `docs/TESTING.md`.
