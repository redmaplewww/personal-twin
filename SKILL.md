---
name: personal-twin
description: 个人数字孪生操作入口——查个人信息/联系方式/账号台账、取凭据、备份、泄露审计。当用户提到 数字孪生 / personal-twin / twin / 我的密码 / 查我(手机|邮箱|微信|QQ|账号) / 凭据 / 密钥 / API key / 个人数据备份 / 脱敏 / 泄露审计 / 恢复个人数据 时使用；涉及把任何个人信息或凭据写入文件前也必须先过本 skill 的红线。
---

# personal-twin —— 个人数字孪生 CLI 操作规约

真相源：`%TWIN_HOME%`（默认 `D:\personal-twin`，本地 git 仓库，不进云同步）。四层模型与红线见你的全局 AGENTS.md「个人数据四层规约」——本 skill 只讲怎么操作。

## 快速路由

| 需求 | 动作 |
|---|---|
| 查公开身份/公开账号 | 读 `%TWIN_HOME%\profile.md`（或问 mem0 类记忆服务） |
| 查手机/邮箱/微信/QQ | 读 `%TWIN_HOME%\contacts.md`（L1，禁止外传上云） |
| 查账号归属/服务器/MCP/SSH 指纹 | 读 `accounts.md` + `inventory\` |
| **在命令中使用凭据** | `twin inject <条目> --env VAR -- <命令>`（值注入子进程 env；省略 --env 则进 stdin）。**AI 取值唯一合法路径**。autounlock 开启时全程免人工。**多字段（base+key）用 inject 链**：`python twin.py inject A --field url --env BASE -- python twin.py inject A --env KEY -- python 脚本.py` |
| 列凭据条目 | `twin list`（无密值；username 中邮箱/手机自动打码） |
| **新凭据入库（AI 主导）** | `twin form <条目> --group X --mode batch --field title=平台名 --field url="Base URL" --field apikey="API Key"` → 把 URL 给用户浏览器填写 → stdout 只收逐条状态。**AI 不得对该页面做 DOM snapshot/截图**（会回显已填值） |
| 新凭据入库（用户自己） | `twin register <条目> ... --token 新L1令牌`（自动联动 accounts.md + audit-tokens + audit + backup） |
| 备份 | `twin backup`（加密 contacts → `%TWIN_BACKUP_DEST%` + kdbx 副本 + git） |
| 泄露审计 | `twin audit`（令牌表 `inventory\audit-tokens.txt`，白名单 `inventory\audit-allowlist.txt`） |
| 新机恢复 | `twin restore <备份目录> --dest %TWIN_HOME%` |

`twin get` 只允许用户本人在终端使用；AI 会话中它被禁用（需要值就 inject）。

## 红线（违反即事故）

1. 任何含 L1（手机/邮箱/微信/QQ/学号）明文或 L3（密码/密钥/token）的内容，**禁止**写入：知识库、mem0 类记忆、任何云同步目录、会话沉淀、输出给外部服务。
2. AI 上下文不接触密值：取值用 inject，入库走 form/register；form 页面填写期间禁止 snapshot/截图。
3. 备份目的地只允许 .enc/.kdbx/README。
4. contacts.md 变更后：同步更新 `inventory\audit-tokens.txt` 并跑 `twin audit` + `twin backup`。
