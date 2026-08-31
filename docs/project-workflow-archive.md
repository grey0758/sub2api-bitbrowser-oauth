# 项目工作流封档说明

本文档记录本项目在本次会话中形成并实际使用过的工作类型、命令、接口契约、结果判定和安全边界，作为后续恢复工作的入口。它只记录流程和脱敏状态；不记录管理员密钥、账号密码、TOTP/2FA 密钥、手机号、短信令牌、OAuth URL、回调 code、Cookie 或完整账号行。

## 1. 封档基线

| 项目 | 固定值/规则 |
| --- | --- |
| 仓库 | `D:\work\sub2api-bitbrowser-oauth` |
| Sub2API 号池 | `https://sub2apiplus.opencodex.uk` |
| API 前缀 | `/api/v1` |
| Workstation 总池 | `https://workstation.opencodex.uk` |
| BitBrowser 窗口 | 精确名称 `us001_codex` |
| BitBrowser API | 默认 `http://127.0.0.1:54345` |
| 本地持久化 | 当前 Windows 用户 DPAPI 加密的 `.runtime/import-pool.dpapi` |
| 远程连接（历史稳定方式） | `ssh-1p ydy001` |

默认管理员凭据只在当前进程注入，变量名为 `SUB2API_ADMIN_TOKEN`、`SUB2API_ADMIN_API_KEY` 或 `SUB2API_ADMIN_COOKIE` 三选一。Workstation 使用 `WORKSTATION_AUTOMATION_TOKEN`。生产密钥的记录位置只保留为：

- OpenBao `projects/sub2api/prod/bitbrowser-oauth` 的 `admin_api_key`；
- OpenBao `projects/opencodex/prod/cliproxy-inventory-api` 的 `WORKSTATION_AUTOMATION_API_TOKEN`；
- `ydy001` 上 ACL 限制的私密 `WORKSTATION_AUTOMATION_API.md`。

这些值不得复制到源码、提交、日志、聊天或普通配置文件。

## 2. 工作类型总览

### 2.1 只读发现和报告

可读取 Sub2API 账号列表、总数、状态、`schedulable` 分布，读取加密号池摘要、健康审计摘要、Workstation ban pool 计数，以及检查唯一的 `us001_codex` 窗口。默认只输出数量和状态；只有操作员明确要求时才输出邮箱清单。生产读取不改变账号、手机号、调度或浏览器配置。

### 2.2 完整 OpenAI OAuth 导入

适用于明确提供的账号、号池中的 pending 账号和 Workstation inventory 账号。流程为：

1. 读取并严格匹配 `us001_codex`，缺失或重名立即停止。
2. 调用 Sub2API `POST /admin/openai/generate-auth-url` 生成一次性授权会话。
3. 在该窗口（通常使用 `--incognito`）打开授权页，选择登录其他账号并输入邮箱、密码。
4. 本地计算 RFC 6238 SHA-1 TOTP；需要时进入手机号和短信验证。
5. 到达 OAuth consent 后由完整导入流程继续授权，捕获 `localhost:1455/auth/callback`，验证 state。
6. 调用 `POST /admin/openai/exchange-code` 交换回调。
7. 按管理员 UI 契约读取 `GET /admin/accounts`：不存在则 `POST /admin/accounts` 创建；存在一个完全相同邮箱则 `POST /admin/accounts/:id/apply-oauth-credentials` 更新。
8. 再次读取账号列表，只有精确邮箱可见时才报告成功。

交换 HTTP 200 只是中间结果，不等于导入成功。

### 2.3 登录-only 探测

`probe-accounts` 从标准输入接收临时的 `email|password|TOTP` 行，仅保留在内存中。它使用固定 BitBrowser 窗口的隔离上下文，登录到 consent 或 phone verification 即停止：

- 不点击 consent；
- 不调用短信、不领取手机号；
- 不交换 callback；
- 不调用 Sub2API 创建/更新；
- 不写入本地池或其他文件。

结果类别为 `login_valid`、`login_valid_phone_required`、`account_banned`、`invalid_credentials`、`rate_limited`、`check_failed`。`check_failed` 只表示未能确认原因，不可直接当作封禁。

### 2.4 健康检查与重新授权

健康工作流按顺序执行：

1. 读取完整账号列表，记录总数、状态和当前调度分布。
2. 对账号逐个调用 `POST /admin/accounts/:id/test`，避免并发冲击上游。
3. 测试完成后再次读取完整列表；以后一次列表为权威结果。
4. `account-health-audit` 将账号 ID、标准化邮箱、状态、错误类别、SHA-256 单向错误指纹和是否存在匹配号池登录材料写入 DPAPI；不保存原始错误、令牌或账号行。
5. `reauthorize-errors` 只处理 `status=error` 且错误被判定为 HTTP 401 或 OAuth token 无效/撤销、同时存在精确本地登录材料的记录。
6. 已被管理系统标记为 banned/disabled 的记录默认跳过；历史 `account_banned` 只有显式 `--retry-banned` 才重试。
7. 重新授权成功必须同时满足 OAuth state、交换成功和精确邮箱在最终列表中可见。批处理遇到真实 OpenAI 限流立即停止。

### 2.5 调度管理

调度状态只能在操作员明确要求时变更。目标账号必须按精确邮箱选定，然后调用管理员契约 `POST /admin/accounts/:id/schedulable`，请求体为 `{ "schedulable": true|false }`，最后重新读取全量列表验证没有意外缺失或禁用值。当前仓库没有单独的 npm 调度命令；复用前应先确认部署端点和实现仍可用。

### 2.6 受控删除

删除永远不能由“状态异常”自动推导。操作员必须明确给出精确邮箱集合。每个目标都要：

1. 重新读取 `GET /admin/accounts`；
2. 要求大小写不敏感的精确邮箱匹配恰好一个；
3. 只调用该 ID 的 `DELETE /admin/accounts/:id`；
4. 删除后重新读取列表，证明每个目标邮箱均已不存在；
5. 保留本地 DPAPI 登录材料，除非另有明确授权。

删除生产记录不可通过本工具恢复。当前 CLI usage 没有独立的 delete 子命令，因此恢复项目时应先验证部署端点和实现，再执行任何删除。

## 3. 浏览器、OAuth 和错误处理

### 3.1 固定窗口规则

- 只允许精确匹配 `us001_codex`，不得创建、删除、清空、刷新或替换其他窗口。
- `release` 只断开 Playwright/CDP；窗口保持打开。
- 只有显式 `--close-window` 才允许关闭该窗口。
- 每次新的授权会话都应重新生成 URL；不得复用旧的 session、state 或 callback。

### 3.2 页面结果分类

| 页面/错误 | 处理 |
| --- | --- |
| `Oops, an error occurred`、`Route Error (500)`、`Unexpected token '<'`、`text/html` | 可恢复路由错误；释放当前隔离上下文，重新生成授权 URL，完整登录流程重试一次（实现允许有限次会话级重试）；不标记封禁、不消耗手机号。 |
| `account_deactivated`、banned、suspended、disabled、terminated 等明确提供商文字 | 确认封禁/停用；记录 `account_banned`，默认跳过后续自动重试。 |
| incorrect/wrong/invalid password | `invalid_credentials`。 |
| 明确的 too many attempts/rate limit/429 | `rate_limited`；停止当前批处理，稍后再开始。 |
| 超时、未知页面或网络失败 | `check_failed`/`route_error`；不能据此断言封禁。 |

### 3.3 手机和短信

- 只有 OpenAI 真正显示手机号页面时才允许准备/领取手机号。
- 美国号码在提交前规范化为十位本地号码（去掉前导 `1`）。
- 短信接口直接由 Node HTTPS 请求；Windows TLS 传输失败时可使用隐藏的 PowerShell `Invoke-WebRequest` 回退，管理员凭据不会传给子进程。
- 每轮 6 次请求、间隔约 10 秒；最多两轮约两分钟。
- 直接 `import-account` 在第一轮失败后允许在两轮之间点击一次 `Resend text message`；从池导入的手机号默认禁止 resend。
- 两轮失败后调用可注入的 `PhoneStatusApi.markInvalid`；默认实现不发网络请求。
- 实际提交手机号时才开始 45 分钟冷却；Workstation 远端手机号最多三次绑定，`binding_count >= 3` 或 `unavailable` 不再领取。
- `pool-reset-phone-cooldowns`、`pool-correct-invalid-phone`、`pool-enable-resend` 都是显式操作，必须保留审计时间和计数；重置冷却不能恢复 invalid 手机。

## 4. 本地号池和 Workstation 总池

### 4.1 本地 DPAPI 号池

账号和手机号从标准输入导入，明文只在进程内存在：

```powershell
npm run pool-import-phones < phones.txt
npm run pool-import-accounts < accounts.txt
npm run pool-status
npm run import-next
```

池文件是 Git 忽略的 `.runtime/import-pool.dpapi`，绑定当前 Windows 用户。CLI 不打印池行。账号状态包括 pending/imported；手机号包括 available/cooldown/invalid。

### 4.2 Workstation inventory

同步和队列导入：

```powershell
npm run inventory-sync-accounts
npm run inventory-import-next -- --incognito
npm run inventory-ban-pool-status
```

主要 API 契约：

- `GET /api/v1/account-inventory/import-lines`：完整账号行，必须视为私密材料，仅合并进 DPAPI。
- `GET /api/v1/account-inventory/ban-pool`：只向 CLI 返回脱敏计数和审计信息。
- `GET /api/v1/phone-inventory/eligible?min_age_minutes=45&limit=1`：只读查找可用手机号。
- `POST /api/v1/phone-inventory/claim`：带 16–128 字符 `Idempotency-Key` 的原子领取；不确定结果必须重用同一 key。
- `PATCH /api/v1/phone-inventory/<phone-id>`：更新 `binding_count` 或 `unavailable`。
- `POST /api/v1/account-inventory/ban-and-replace`：仅在明确授权时，以精确本地邮箱和幂等 key 原子封禁并替换。
- `PATCH /api/v1/account-inventory/ban-pool/<ban-id>`：将记录标记为 `banned_replaced`，幂等。
- `POST /api/v1/account-inventory/ban-pool/extract-pending-replacements`：一次性提取待替换批次；只能通过带私有 `consume` 回调的库方法使用，没有打印批次的 CLI。

Workstation 的标准状态为 `available`、`sold`、`imported`、`banned`、`banned_replaced`、`reauthorization_pending`；旧值 `unsold/pending/destroyed` 分别归一化为 `available/available/banned_replaced`。

## 5. 命令速查

```text
npm ci
npm test
npm run syntax
npm run check
npm run start
npm run run
npm run import-account
npm run probe-accounts < accounts.txt
npm run import-next
npm run inventory-sync-accounts
npm run inventory-import-next
npm run inventory-ban-pool-status
npm run inventory-ban-and-replace -- --email EMAIL
npm run account-health-audit
npm run reauthorize-errors -- --limit N
npm run reauthorize-errors -- --email EMAIL
npm run reauthorize-errors -- --retry-failed
npm run reauthorize-errors -- --retry-banned
npm run reauthorize-errors -- --replace-banned
npm run pool-import-phones < phones.txt
npm run pool-import-accounts < accounts.txt
npm run pool-status
npm run pool-reset-phone-cooldowns
npm run pool-correct-invalid-phone
npm run pool-enable-resend
npm run test:dependencies
```

`start` 只生成并打开授权页；`run` 还会等待并交换 callback；`import-account` 才会执行账号 create/update；`probe-accounts` 永远不导入。

## 6. 本次会话形成的历史记录

以下是工作类型和结果类别的脱敏摘要，不是当前生产快照。封档后如需真实状态，必须重新执行只读列表、健康测试和审计：

- 曾将默认操作目标切换并固定为 Plus 号池 `sub2apiplus.opencodex.uk`，验证管理员访问和 `us001_codex` 窗口。
- 曾通过真实依赖测试验证 DPAPI 加密池、假账号/假手机号、Workstation 客户端、幂等领取、冷却和 invalid 路径；测试池随后清理，不创建生产测试账号或领取生产手机号。
- 曾对一批错误账号进行健康审计和登录式重新授权；历史 UI 数量与实际可重试数量出现过差异，必须以后置账号列表为准。
- 曾遇到限流、OpenAI `account_deactivated`、路由 500 和 HTML/JSON 解析错误；已建立“明确封禁才记 banned、路由错误重新生成授权会话、限流停止批处理”的判定规则。
- 曾输出过封禁/错误账号的脱敏清单，并按操作员明确指定的邮箱批次执行过受控删除请求；删除后应始终做精确邮箱缺失验证。
- 曾请求为正常账号开启调度；调度变更必须是显式操作并在变更后重新读取验证。
- 最近一次单账号登录-only 探测结果为 `check_failed`：未确认登录有效、手机号要求、封禁、密码错误或限流；没有交换 callback、导入或写入资料。
- 代码验证曾通过 Node 单元测试、语法检查和固定窗口检查；恢复工作时仍应重新运行这三项。

历史数量快照（仅用于理解会话，不是当前生产结论）：

- 某次管理页面显示 64 条错误记录；随后审计识别出其中 40 条实际错误账号。
- 后续 Plus 号池快照曾有 63 条记录，其中 62 条为明确的 401/OAuth 失败，另有 1 条 active 记录缺少本地登录材料。
- 会话中确认过 13 个提供商封禁账号，并收到过 9 个错误账号的明确删除批次请求；任何删除结果都必须以删除后的精确邮箱列表复核为准。
- 号池状态、错误数和封禁数会随生产调度变化；封档后必须重新执行只读快照，不得沿用以上数字。

## 7. 文档、账号管理接入与发布边界

本会话还完成或验证过以下交付能力：

- 将完整导入、登录-only 探测、健康审计、错误账号重新授权和号池队列接入账号管理系统的管理员 API，而不是直接写数据库或账号文件。
- 为 Workstation inventory 整理了非私密接口契约文档；私密 API 文档继续留在 `ydy001` 本地并由 ACL 和 Git ignore 保护。
- 使用 OpenBao 作为管理员密钥和 Workstation token 的权威来源；部署机只 materialize 运行时文件，运行时文件不进入 Git。
- 曾在 `ydy001` 通过 Tailscale 直连 SSH 验证部署和 `us001_codex`，未修改 DNS、SSH、Tailscale、Mihomo、FRP、Cloudflare 或生产容器配置。
- 代码、文档、测试和语法检查可以作为一次发布批次；提交、推送 GitHub 或部署到 `ydy001` 必须由操作员单独明确要求，不能由普通诊断或导入操作隐式触发。

历史交付报告曾提到 GitHub `main` 的提交和 `ydy001` 部署已对齐；该信息只作来源线索，不覆盖当前工作树。恢复时以 `git status --short`、当前分支和远端实际状态为准，绝不执行 `reset --hard` 或覆盖用户修改。

## 8. 封档后的恢复顺序

1. 先阅读本文档和根目录 `AGENTS.md`，确认工作类型没有被新指令替换。
2. 检查 `git status --short`，保留已有修改、`tmp/` 和 Git 忽略的私密文件，不执行破坏性清理。
3. 执行 `npm ci`（依赖缺失时）以及 `npm test`、`npm run syntax`、`npm run check`。
4. 在当前进程注入一个管理员凭据；Workstation 任务另行注入 automation token。
5. 先做只读快照：Sub2API 列表、`pool-status`、必要时 `inventory-sync-accounts` 和 `inventory-ban-pool-status`。
6. 只有操作员明确指定后，才进行导入、重新授权、调度、ban-and-replace 或删除。
7. 任何生产变更完成后，都要重新读取最终列表并输出脱敏计数；不要把密钥、账号行或 callback 写入封档文档。

## 9. 明确禁止事项

- 不创建、删除或切换非 `us001_codex` 的 BitBrowser 窗口。
- 不把管理员凭据、Workstation token、账号密码、TOTP、手机号、短信令牌、OAuth URL/code、Cookie 或 provider token 写入仓库、日志或聊天。
- 不用浏览器打开短信 API，不在 probe 中领取手机号，不把 probe 输入持久化。
- 不直接改 PostgreSQL、Redis、账号文件、NewAPI channels/abilities、proxy bindings、DNS、Cloudflare、SSH、Tailscale、Mihomo 或生产容器。
- 不从状态名称推断删除目标，不进行批量/模糊删除，不删除本地 DPAPI 登录材料。
- 不把 HTTP 200 exchange、一次测试请求成功或未知网络失败误报为账号已修复。
