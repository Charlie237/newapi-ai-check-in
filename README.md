# newapi-ai-check-in

面向 NewAPI 系站点的多账号自动化签到项目，支持主流程签到、站点差异化登录链路、缓存复用和统一摘要通知。

## 当前工作流

- `checkin.yml`
  - 主流程：多 provider 签到
  - 支持 `cookies`、`user(用户名/邮箱+密码)`、`github`、`linux.do` 多认证方式
- `checkin-hybgzs.yml`
  - `hybgzs` 自动签到
  - 可选大转盘（`wheel: true`）
- `checkin-qaq-al.yml`
  - `qaq.al` 自动签到
  - 支持 LinuxDo 自动登录并自动获取/刷新 `sid`
- `immortality.yml`
  - 定时保活，避免 workflow 长期不触发

已移除：
- `checkin_996` 相关脚本与 workflow
- LinuxDo 读帖 workflow

## 额外实现（本项目增强点）

- AnyRouter / NewAPI 站点支持 `user` 密码登录链路（邮箱或用户名）
- 密码登录成功后自动提取 cookie + `api_user`，写入本地缓存供后续复用
- `cookies` 认证改为数组模型，支持同一账号下多个 cookie 身份
- `hybgzs` 支持自动签到 + 大转盘
- `qaq.al` 支持自动获取 `sid`（LinuxDo 优先，`sid` 回退）
- 通知从长文本明细改为统一摘要模板（更短、更可读）
- `get_cdk_cookies` 仍保留可用（如 runawaytime/b4u 相关链路）

## Secrets 配置总览

所有 secrets 建议配置在 `Environment: production`。

### 主流程 `ACCOUNTS`（`checkin.yml`）

```json
[
  {
    "name": "AnyRouter 密码登录",
    "provider": "anyrouter",
    "user": [
      {"username": "your_email_or_username", "password": "your_password"}
    ],
    "linux.do": true
  },
  {
    "name": "AnyRouter Cookies",
    "provider": "anyrouter",
    "cookies": [
      {"session": "your_session_value", "api_user": "123456"},
      {"cookies": {"session": "another_session"}, "api_user": "654321"}
    ]
  }
]
```

关键规则：
- `user` 仅支持数组格式
- 根字段 `username/password` 已废弃
- `cookies` 在主流程中仅支持数组格式
- 每个 `cookies[i]` 必须带 `api_user`
- `linux.do` 和 `github` 仍支持 `true | object | array`
- `runawaytime` 可选账号级参数 `runaway_max_wheel_spins`：
  - 默认 `0`（本次转盘转到不能转为止）
  - 设置正整数可限制本次最大转盘次数

### 全局账号池（可选）

`ACCOUNTS_LINUX_DO`：

```json
[
  {"username": "linuxdo_user_1", "password": "linuxdo_pass_1"},
  {"username": "linuxdo_user_2", "password": "linuxdo_pass_2"}
]
```

`ACCOUNTS_GITHUB`：

```json
[
  {"username": "github_user_1", "password": "github_pass_1"}
]
```

### `hybgzs` 工作流

`ACCOUNTS_HYBGZS`：

```json
[
  {"name": "hybgzs-main", "linux.do": true, "wheel": true},
  {"name": "hybgzs-backup", "cookies": {"__Secure-next-auth.session-token": "your_cookie"}, "wheel": false}
]
```

可选：
- `max_wheel_spins`：账号级参数，写在 `ACCOUNTS_HYBGZS[*].max_wheel_spins`，默认 `0`，`0` 表示本次跑完全部剩余次数
- `PROXY_HYBGZS`

### `qaq.al` 工作流

`ACCOUNTS_QAQ_AL`：

```json
[
  {"name": "qaq-main", "linux.do": true, "tier": 4},
  {"name": "qaq-fallback", "sid": "your_sid", "tier": 4}
]
```

可选：
- `tier`：账号级参数，写在 `ACCOUNTS_QAQ_AL[*].tier`，默认 `4`
- `PROXY_QAQ_AL`

## 认证执行顺序（主流程）

单个账号内会按顺序尝试以下认证方式，结果独立统计：

1. `cookies`
2. `user`
3. `github`
4. `linux.do`

说明：
- 同一个账号下如果同时配置了多种方式，会依次执行，不互斥
- 某方式失败不会阻塞后续方式继续尝试

## 缓存机制

缓存目录：`storage-states/`（workflow 中通过 cache 恢复）

已缓存内容包括：
- provider 登录态 / cookies 缓存
- LinuxDo OAuth 状态缓存
- `hybgzs` 相关状态
- `qaq.al` 的 `sid`/状态缓存
- `balance_hash*.txt`（用于余额变化通知去重）

## 通知摘要格式（新）

主流程通知使用统一摘要模板，示例：

```text
[Check-in Summary]
time: 2026-02-17 21:00:00
workflow: main/checkin
status: partial
success: 8/10
failed: 2/10
accounts_success: 4/5
auth_methods_success: 8/10
trigger: partial_failure; balance_changed
failed_accounts: 账号A(user:401); 账号B(cookies:expired)
partial_accounts: 账号C(ok:user fail:linux.do)
highlights: 账号D(ok:cookies,user); 账号E(ok:linux.do)
```

字段说明：
- `status`：`success | partial | failed | unknown`
- `success/failed`：按账号统计
- `accounts_success`：成功账号数
- `auth_methods_success`：认证方式维度成功数
- `trigger`：触发通知原因（如 `first_run`、`balance_changed`、`account_failure`、`partial_failure`）
- 通知格式可选：`detail | summary | both`
  - 主流程：`CHECKIN_NOTIFY_FORMAT`
  - qaq.al：`QAQ_AL_NOTIFY_FORMAT`
  - hybgzs：`HYBGZS_NOTIFY_FORMAT`

## 可用通知渠道

- `DINGDING_WEBHOOK`
- `EMAIL_USER`, `EMAIL_PASS`, `EMAIL_TO`, `CUSTOM_SMTP_SERVER`
- `PUSHPLUS_TOKEN`
- `SERVERPUSHKEY`
- `FEISHU_WEBHOOK`
- `WEIXIN_WEBHOOK`
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`

## 本地运行

```bash
uv sync --dev
uv run camoufox fetch
uv run python -u main.py
```

## 快速排查清单

1. `ACCOUNTS` 是否使用 `user` 数组而非根 `username/password`
2. `cookies` 是否为数组，且每项都包含 `api_user`
3. 每个账号是否至少存在一种可用认证方式
4. 全局账号池 `ACCOUNTS_LINUX_DO` / `ACCOUNTS_GITHUB` 是否是合法 JSON 数组
5. 目标站点是否已变更登录/签到接口（必要时查看 workflow logs）

## 免责声明

仅用于学习与自动化研究，请遵守目标站点条款与当地法律法规。
