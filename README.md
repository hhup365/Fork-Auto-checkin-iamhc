# iamhc 自动签到脚本

自动登录 [api.hcnsec.cn](https://api.hcnsec.cn)并执行每日签到，签到后通过 Telegram 推送通知(可选)。

## 适配内容

- 支持多账号环境变量配置，按 `EMAIL_1/2/3`、`PASSWORD_1/2/3`、`PROXY_URL_1/2/3` 组织。
- 每个账号可独立配置代理，脚本会为每个账号生成独立的本地 8080 代理配置并通过 sing-box 启动。
- 工作流会自动下载 sing-box 内核并调用 [proxyurl.py](proxyurl.py) 生成代理配置。
- 也兼容旧版单账号环境变量 `EMAIL`、`PASSWORD`、`PROXY_URL`。
- **自动两步验证（2FA）**：登录触发 2FA 时，用 `OTP_SECRET` 生成 TOTP 验证码提交（端点 `POST /api/user/login/2fa`）；容忍 ±30 秒时钟偏差，并在账户被临时锁定时自动等待 16 分钟后重试一次。
- **登录会话复用**：登录成功后把会话保存到加密仓库变量 `IAMHC_SESSIONS`，下次运行优先复用、**跳过登录与 2FA**；会话失效时自动重新登录并刷新。
- **代理出口 IP 排查**：运行时打印打码后的直连出口 IP 与代理出口 IP（如 `192.*.*.100`），两者相同说明代理未生效，获取失败说明节点已失效。
- **健壮性**：登录连接异常自动重试；代理不可用自动降级直连；单个账号异常不影响其他账号；全部失败时以非零码退出便于在 Actions 中察觉。

### 配置 Secrets

在仓库 **Settings → Secrets and variables → Actions → Secrets** 中添加以下 Secrets：

| Secret 名称 | 说明 |
|-------------|------|
| `EMAIL_1` | 第 1 个账号邮箱(可选) |
| `PASSWORD_1` | 第 1 个账号密码(可选) |
| `PROXY_URL_1` | 第 1 个账号代理链接(可选) |
| `OTP_SECRET_1` | 第 1 个账号的 2FA 密钥(可选)，支持 Base32 或完整 `otpauth://` 链接 |
| `EMAIL_2` / `PASSWORD_2` / `PROXY_URL_2` / `OTP_SECRET_2` | 第 2 个账号(可选) |
| `EMAIL_3` / `PASSWORD_3` / `PROXY_URL_3` / `OTP_SECRET_3` | 第 3 个账号(可选) |
| `TG_BOT_TOKEN` | Telegram Bot Token(可选) |
| `TG_CHAT_ID` | Telegram Chat ID(可选) |
| `GH_PAT` | 用于持久化登录会话的细粒度 PAT，**强烈建议配置**，详见下节 |

### 配置 GH_PAT（持久化登录会话，推荐）

登录会话保存在仓库变量 `IAMHC_SESSIONS` 里，写回该变量需要 `Variables` 写权限。默认的 `GITHUB_TOKEN` 在部分仓库策略下无法写变量，因此建议配置一个加密的细粒度 PAT：

> 注意：Secret 名称**不能**以 `GITHUB_` 开头（该前缀被 GitHub 保留，创建会被拒绝），因此这里使用 `GH_PAT`。

1. 打开 [github.com/settings/personal-access-tokens/new](https://github.com/settings/personal-access-tokens/new) 创建 **Fine-grained personal access token**。
2. **Resource owner** 选你自己，**Repository access** 选 **Only select repositories** 并勾选本仓库。
3. **Repository permissions** 中把 **Variables** 设为 **Read and write**（其余保持 No access 即可）。
4. 生成后复制 token，到仓库 **Settings → Secrets and variables → Actions → Secrets** 新建名为 `GH_PAT` 的 Secret 粘贴保存。

> 未配置 `GH_PAT` 时工作流会自动回退到默认 `GITHUB_TOKEN`；若日志出现「写入仓库变量失败」，即表示需要按上面步骤补配 `GH_PAT`。会话数据始终以加密变量形式保存，不会明文写入仓库文件。

### 首次运行说明

首次运行（或会话过期后）仍需正确的 `OTP_SECRET_x` 完成一次 2FA；成功后会话被保存，之后的运行会自动复用、跳过 2FA。请确认 `OTP_SECRET` 填的是验证器密钥本身（若复制的是 `otpauth://` 链接，脚本会自动提取其中的 `secret` 参数）。

### 手动触发

在仓库 **Actions** 页面选择 `iamhc Daily Checkin` 工作流，点击 **Run workflow** 即可手动触发。

## 获取 Telegram Bot Token 和 Chat ID

1. 在 Telegram 中搜索 `@BotFather`，发送 `/newbot` 创建机器人，获取 **Bot Token**
2. 搜索 `@userinfobot`，发送任意消息，获取你的 **Chat ID**
3. 先给你的 Bot 发一条消息（激活会话），否则 Bot 无法主动推送
