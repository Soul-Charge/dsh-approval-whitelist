# 如何测试这个插件

三层测试，从"完全不碰 DSH"到"在真实会话里验收"。**全部只读 DSH 配置**，
唯一会改到 DSH 的是第 3 层里你自己发起的提权调用。

## 第 0 层：一键自检（最常用）

在**已安装**目录跑（也可以在项目目录跑）：

```bash
node /home/user/.dsh/plugins/dsh-approval-whitelist/tools/verify-live.mjs \
     --source /mnt/f/workspace/projects/dsh-approval-whitelist
```

它回答 6 个问题，任何一项不过就 exit code=1：

| # | 检查 |
|---|---|
| 1 | 已安装的字节是否还等于**被测过的那份源码**（逐文件 md5） |
| 2 | 模块能否加载（`name=approval-whitelist`、`apply` 是函数） |
| 3 | 规则库能否解析；哪些规则**当前生效**（`LIVE`） |
| 4 | 用**线上规则 + 线上代码**重放真实 23 条提权请求（期望 22/23） |
| 5 | 5 条兜底是否仍被拒（删除 / sudo / 设备 / 凭据 / 根外写入） |
| 6 | 审计日志行数与结果分布 |

上次实跑输出：

```
[1] source comparison: 17/17 files identical
[3] rule store ... rules=1 load errors=0
    LIVE  r1  level=data  scope=global  expires=never  /home/user/myproject/data/plugins
[4] replay of the 23 real escalation requests with the live rules: 22 auto-allowed
[5] 5/5 backstops refused
VERDICT: all checks passed
```

## 第 1 层：单元 + 负向 + 回放（不碰 DSH，秒级）

```bash
cd /home/user/.dsh/plugins/dsh-approval-whitelist
node test/run-all.mjs
```

四个套件、68 条断言：

| 套件 | 断言数 | 测什么 |
|---|---|---|
| `test/unit.mjs` | 26 | 路径规范化/盘符别名、shell 分解、写入目标提取、guard、规则与存储 |
| `test/negative.mjs` | 29 | **红线必须全拦**（29 条）+ 5 条正向对照 |
| `test/replay.mjs` | 6 | 真实 23 条提权请求回放（含"误放行必须为 0"的断言） |
| `test/integration.mjs` | 7 | 真实 cordis + dsh-tools + dsh-user-approval，**不含 auto-mode** |

退出码非 0 即失败。产物落在 `$TMPDIR/dsh-approval-whitelist-tests/`
（**不在插件目录内**，所以只读安装目录也能跑；用 `AW_TEST_TMP=...` 可改到别处）。

### 只跑其中一层

```bash
node test/unit.mjs          # 或 negative.mjs / replay.mjs / integration.mjs
```

### 换一个可信根跑回放

回放默认拿规则库/用例里的路径；要验证"换一个根会不会更严/更松"：

```bash
node test/replay.mjs /home/user/myproject/data/plugins
```

## 第 2 层：决策引擎单点问询（不碰 DSH，给任意命令打分）

想知道**某一条具体命令**会不会被放行，不必真的执行它：

```bash
cd /home/user/.dsh/plugins/dsh-approval-whitelist
node --input-type=module -e '
import { loadState } from "./src/store.js"
import { activeRules, decide } from "./src/rules.js"
const { state } = loadState(process.env.HOME + "/.dsh/approval-whitelist.json", () => {})
const rules = activeRules(state, "probe", Date.now())
const ask = (tool, args) => decide({ rules, tool, args, sessionCwd: "/mnt/f/workspace",
  workspace: "/mnt/f/workspace", sessionId: "probe", home: process.env.HOME,
  dshHome: process.env.HOME + "/.dsh", protectDshHome: false, guardEnabled: true })
for (const [label, tool, args] of [
  ["白名单内 edit", "edit", { file_path: "/home/user/myproject/data/plugins/x/main.py" }],
  ["白名单内脚本", "bash", { command: "python3 /mnt/f/workspace/tasks/apply.py" }],
  ["根外写入",     "bash", { command: "cp /home/user/myproject/data/plugins/a /tmp/b" }],
  ["删除",         "bash", { command: "rm -rf /home/user/myproject/data/plugins/x" }],
  ["sudo",         "bash", { command: "sudo ls" }],
]) {
  const d = ask(tool, args)
  console.log((d.allow ? "ALLOW " : "pass  ") + label.padEnd(16) + " code=" + d.code + "  " + d.reason)
}
'
```

## 第 3 层：真实端到端验收（会真的调用 DSH 审批链）

这是唯一能证明"**弹窗真的没了**"的方法，因为会话日志无法区分"自动放行"和"人工点允许"。

**判据是三段式的，缺一不可：**

1. **基线**：不带提权，在可信根里写文件 → 必须被沙箱拒绝
   （`OSError: [Errno 30] Read-only file system`），证明提权确实需要；
2. **处理**：同一条命令带 `danger-full-access` → **不应出现审批弹窗**，直接执行成功；
3. **证据**：`~/.dsh/approval-whitelist.audit.log` 新增一行
   `"result":"allowed-once"`，且 `ruleId`/`level` 是预期的那条规则
   —— **只有本插件的 listener 返回 `allowed-once` 才会写这一行**。

在 UI 里让 agent 执行下面这段（探针会自己删掉自己）：

```bash
python3 -c 'import pathlib; p=pathlib.Path("/home/user/myproject/data/plugins/.probe"); p.write_text("ok"); print("WROTE", p.stat().st_size); p.unlink(); print("REMOVED", p.exists())'
```

- 先**不带** `sandbox_permissions` 跑一次 → 应报 `Read-only file system`；
- 再**带** `sandbox_permissions: "danger-full-access"` 跑一次 → 应直接成功且**不弹窗**；
- 然后查审计：

```bash
tail -3 ~/.dsh/approval-whitelist.audit.log | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const l of s.trim().split("\n")){const e=JSON.parse(l);console.log(new Date(e.ts).toISOString(),e.result,e.code,"rule="+e.ruleId,"level="+e.level,e.tool)}})'
```

**2026-09-22 20:12 的真实结果**（已跑通）：

```
WROTE 2 / REMOVED False
2026-09-22T12:12:28.346Z  allowed-once  allowed  rule=r1  level=data  bash
```

### 反向验收（必须照旧弹窗）

同一条命令写到**规则根之外**（例如 `/tmp/probe`），应仍然弹窗并要求你批准。
不弹 = 判据外泄，属于必须立刻回滚的严重问题。

### 规则热生效验收

```
/permit add /tmp/aw-demo data global
```
然后往 `/tmp/aw-demo` 里提权写一个文件 → 应直接放行（**无需重启 DSH**）。
最后 `/permit rm <id>`，同一个写入应恢复弹窗。

## 第 4 层：guard 存活性探针（判断插件到底有没有加载）

启动日志里不一定有 `[approval-whitelist]` 行（`ctx.logger.info` 在某些路径不落 console），
所以**不要用"没有日志"推断"没加载"**。用行为探针：

```bash
# 让 agent 执行：写一个系统路径
# 期望失败，且理由是我们 guard 的措辞 —— system path /etc/...
```

在 UI 里让 agent 调 `write` 写 `/etc/anything`：
- 返回 `Error: system path /etc/...` → **我们的 guard 在跑**（profile 里没有第二个会拦 `write` 的 guard）；
- 返回别的沙箱错误 → 插件可能没加载，检查 `dsh.profile.bundles` 与 `dsh plugin list`。

## 常见问题

| 症状 | 原因 / 处理 |
|---|---|
| `node test/run-all.mjs` 报 `ENOENT … test/.tmp/…` | 旧版本测试曾在插件目录里建临时目录；已改为写到 `$TMPDIR/dsh-approval-whitelist-tests`。若仍报错说明装的是旧副本，重新同步 `test/`。 |
| 集成测试报 `Cannot find package '@deepseek-ai/...'` | 缺少 `node_modules` 链接。在插件目录执行 `ln -sfn /home/user/.dsh/profiles/node_modules node_modules`。 |
| `replay` 里 23 条只放行 6 条 | 规则是 `code` 级。`code` 只放行可静态证明的纯写入；22/23 需要 `data` 级。这是**设计行为**，不是 bug。 |
| 审计里 `target: []` | 真实调用经 `run_code` → ptc 子派发，子调用 callId 与登记时不同，目标列表为空。放行判定正确，仅审计字段缺失（已知待修）。 |
| 想验证"用例是不是编的" | `test/cases.json` 由 `tools/extract-cases.mjs` 从 DSH 会话日志抽取：`node tools/extract-cases.mjs --file <session.jsonl.zstd> --out test/cases.json`。会话日志是多帧 zstd，用 `tools/session-cases.mjs` 里的 `readLog()` 读。 |

## 回归到项目目录

测完记得把改动同步回来，并确认两边一致：

```bash
node /home/user/.dsh/plugins/dsh-approval-whitelist/tools/verify-live.mjs \
     --source /mnt/f/workspace/projects/dsh-approval-whitelist
```

第 1 项 `17/17 files identical` 即两边同步。
