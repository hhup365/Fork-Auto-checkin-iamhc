# iamhc 自动签到脚本

自动登录 [api.hcnsec.cn](https://api.hcnsec.cn)并执行每日签到，签到后通过 Telegram 推送通知(可选)。

## 适配内容

- 支持多账号环境变量配置，按 `EMAIL_1/2/3`、`PASSWORD_1/2/3`、`PROXY_URL_1/2/3` 组织。
- 每个账号可独立配置代理，脚本会为每个账号生成独立的本地 8080 代理配置并通过 sing-box 启动。
- 工作流会自动下载 sing-box 内核并调用 [proxyurl.py](proxyurl.py) 生成代理配置。
- 也兼容旧版单账号环境变量 `EMAIL`、`PASSWORD`、`PROXY_URL`。

### 配置 Secrets

在仓库 **Settings → Secrets and variables → Actions** 中添加以下 Secrets：

| Secret 名称 | 说明 |
|-------------|------|
| `EMAIL_1` | 第 1 个账号邮箱(可选) |
| `PASSWORD_1` | 第 1 个账号密码(可选) |
| `PROXY_URL_1` | 第 1 个账号代理链接(可选) |
| `EMAIL_2` | 第 2 个账号邮箱(可选) |
| `PASSWORD_2` | 第 2 个账号密码(可选) |
| `PROXY_URL_2` | 第 2 个账号代理链接(可选) |
| `EMAIL_3` | 第 3 个账号邮箱(可选) |
| `PASSWORD_3` | 第 3 个账号密码(可选) |
| `PROXY_URL_3` | 第 3 个账号代理链接(可选) |
| `OTP_SECRET_1` | 第 1 个账号的 2FA/Base32 密钥(可选) |
| `OTP_SECRET_2` | 第 2 个账号的 2FA/Base32 密钥(可选) |
| `OTP_SECRET_3` | 第 3 个账号的 2FA/Base32 密钥(可选) |
| `TG_BOT_TOKEN` | Telegram Bot Token(可选) |
| `TG_CHAT_ID` | Telegram Chat ID(可选) |

### 手动触发

在仓库 **Actions** 页面选择 `iamhc Daily Checkin` 工作流，点击 **Run workflow** 即可手动触发。

## 获取 Telegram Bot Token 和 Chat ID

1. 在 Telegram 中搜索 `@BotFather`，发送 `/newbot` 创建机器人，获取 **Bot Token**
2. 搜索 `@userinfobot`，发送任意消息，获取你的 **Chat ID**
3. 先给你的 Bot 发一条消息（激活会话），否则 Bot 无法主动推送
