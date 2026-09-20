#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, quote, urlparse

import requests

TG_CHAT_ID = os.environ.get("TG_CHAT_ID") or ""
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN") or ""

BASE_URL = "https://api.hcnsec.cn"
QUOTA_PER_UNIT = 500000
TURNSTILE_TOKEN = ""
LOCAL_PROXY_URL = os.environ.get("LOCAL_PROXY_URL", "http://127.0.0.1:8080").strip()
OTP_SECRET = os.environ.get("OTP_SECRET", "").strip()

# 连接层异常（超时/被重置等）时的返回标记，区别于 HTTP 状态码
CONN_ERROR = "conn_error"
# 2FA 账户锁定标记
LOCKED = "locked"

# 登录会话复用：从仓库变量 IAMHC_SESSIONS 读取上次会话，运行结束后由工作流
# 用 gh variable set 写回（避免明文写入仓库文件）。
SESSIONS_ENV = "IAMHC_SESSIONS"
SESSIONS_UPDATE_ENV = "IAMHC_SESSIONS_UPDATE"
SESSION_COOKIE_NAME = "session"
COOKIE_DOMAIN = urlparse(BASE_URL).hostname or ""

# 出口 IP 检测服务（用于排查代理是否生效，输出打码 IP）
IP_CHECK_URLS = (
    "https://api.ipify.org?format=json",
    "https://api.ip.sb/json/ip",
    "http://ip-api.com/json/",
)


def mask_ip(ip):
    """将出口 IP 打码显示（如 192.*.*.100），方便排查代理又不泄露完整地址。"""
    ip = str(ip).strip()
    if ":" not in ip and ip.count(".") == 3:
        first, _, rest = ip.partition(".")
        last = rest.rsplit(".", 1)[-1]
        return f"{first}.*.*.{last}"
    if ":" in ip:
        groups = [g for g in ip.split(":") if g]
        if len(groups) >= 3:
            return f"{groups[0]}:{groups[1]}:*:*:{groups[-1]}"
    return "*"


def fetch_exit_ip(proxies=None, timeout=10):
    """通过指定代理（None 表示直连）访问 IP 回显服务，返回出口 IP 或 None。"""
    session = requests.Session()
    session.trust_env = False
    if proxies:
        session.proxies.update(proxies)
    for url in IP_CHECK_URLS:
        try:
            resp = session.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                data = {}
            for key in ("ip", "query", "ipAddress", "ip_addr"):
                if data.get(key):
                    return str(data[key]).strip()
        except requests.RequestException:
            continue
    return None


def normalize_secret(secret: str) -> str:
    if not secret:
        return ""
    secret = str(secret).strip()
    # 支持 otpauth:// 链接：自动提取其中的 secret 参数
    if secret.lower().startswith("otpauth://"):
        try:
            secret = (parse_qs(urlparse(secret).query).get("secret") or [""])[0]
        except Exception:
            return ""
    cleaned = re.sub(r"[\s\-_=]+", "", secret).upper()
    if not cleaned:
        return ""
    return cleaned


def mask_username(username: str) -> str:
    if not username:
        return username
    username = str(username)
    if "@" in username:
        local, _, domain = username.partition("@")
        if len(local) <= 2:
            masked_local = local[0] + "*" * max(1, len(local) - 1)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"
    if len(username) <= 2:
        return username[0] + "*"
    return username[0] + "*" * (len(username) - 2) + username[-1]


def generate_totp_code(secret: str, digits: int = 6, period: int = 30, at=None):
    secret = (secret or OTP_SECRET or "").strip()
    if not secret:
        return ""

    normalized_secret = normalize_secret(secret)
    if normalized_secret:
        try:
            secret_bytes = base64.b32decode(normalized_secret + "=" * ((8 - len(normalized_secret) % 8) % 8))
        except Exception:
            try:
                secret_bytes = bytes.fromhex(normalized_secret)
            except ValueError:
                secret_bytes = normalized_secret.encode("utf-8")
    else:
        secret_bytes = secret.encode("utf-8")

    timestamp = int(at if at is not None else time.time()) // period
    msg = timestamp.to_bytes(8, "big")
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    code = str(binary % (10 ** digits)).zfill(digits)
    return code


def load_accounts_from_env():
    """从环境变量加载账号配置，支持 ACCOUNTS_JSON、EMAIL_1/2/3... 和兼容单账号模式。"""
    accounts_json = os.environ.get("ACCOUNTS_JSON", "").strip()
    if accounts_json:
        try:
            data = json.loads(accounts_json)
        except json.JSONDecodeError as exc:
            print(f"ACCOUNTS_JSON 解析失败: {exc}")
            return []

        if isinstance(data, dict):
            if isinstance(data.get("accounts"), list):
                data = data["accounts"]
            else:
                data = [data]

        if not isinstance(data, list):
            return []

        accounts = []
        for item in data:
            if isinstance(item, dict):
                accounts.append(
                    {
                        "email": str(item.get("email") or "").strip(),
                        "password": str(item.get("password") or "").strip(),
                        "proxy_url": str(item.get("proxy_url") or "").strip(),
                        "otp_secret": str(item.get("otp_secret") or "").strip(),
                    }
                )
        return accounts

    accounts = []
    for index in range(1, 10):
        email = os.environ.get(f"EMAIL_{index}", "").strip()
        password = os.environ.get(f"PASSWORD_{index}", "").strip()
        proxy_url = os.environ.get(f"PROXY_URL_{index}", "").strip()
        if any([email, password, proxy_url]):
            accounts.append(
                {
                    "email": email,
                    "password": password,
                    "proxy_url": proxy_url,
                    "otp_secret": os.environ.get(f"OTP_SECRET_{index}", "").strip(),
                }
            )

    if accounts:
        return accounts

    if os.environ.get("EMAIL", "").strip() or os.environ.get("PASSWORD", "").strip() or os.environ.get("PROXY_URL", "").strip():
        return [
            {
                "email": os.environ.get("EMAIL", "").strip(),
                "password": os.environ.get("PASSWORD", "").strip(),
                "proxy_url": os.environ.get("PROXY_URL", "").strip(),
                "otp_secret": os.environ.get("OTP_SECRET", "").strip(),
            }
        ]

    return []


def build_session(account, proxy_ready=False):
    session = requests.Session()
    session.trust_env = False
    if proxy_ready and account.get("proxy_url"):
        proxy_address = LOCAL_PROXY_URL
        session.proxies = {"http": proxy_address, "https": proxy_address, "all": proxy_address}
        print(f"🔀 代理已启用 | {proxy_address}")
    else:
        session.proxies = {}
        print("🔓 代理未就绪，将直接连接")
    return session


def load_session_store():
    """从环境变量读取上次保存的登录会话：{账号序号: {cookie, user_id, username}}。"""
    raw = os.environ.get(SESSIONS_ENV, "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print("⚠️ 已保存会话数据解析失败，将全部重新登录")
        return {}
    return data if isinstance(data, dict) else {}


def export_session_store(store):
    """把最新会话写入 GITHUB_ENV，由工作流用 gh variable set 写回仓库变量。

    不打印内容，避免会话泄露到运行日志。
    """
    github_env = os.environ.get("GITHUB_ENV")
    if not github_env or not store:
        return
    try:
        with open(github_env, "a", encoding="utf-8") as fh:
            fh.write(f"{SESSIONS_UPDATE_ENV}={json.dumps(store, ensure_ascii=False)}\n")
    except OSError as exc:
        print("保存会话到 GITHUB_ENV 失败:", exc)


def resolve_singbox_path(path):
    if not path:
        return ""
    if os.path.isabs(path):
        return path

    repo_root = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(repo_root, path))


def start_local_proxy(account, account_index, total_accounts):
    if not account.get("proxy_url"):
        return None, None

    repo_root = os.path.dirname(os.path.abspath(__file__))
    proxy_script = os.path.join(repo_root, "proxyurl.py")
    temp_dir = tempfile.mkdtemp(prefix=f"iamhc-proxy-{account_index}-", dir=repo_root)

    print(f"🧩 正在为账号 {account_index}/{total_accounts} 生成本地代理配置...")
    proxy_env = os.environ.copy()
    proxy_env["PROXY_URL"] = account["proxy_url"]

    proxy_generation = subprocess.run(
        [sys.executable, proxy_script],
        cwd=temp_dir,
        env=proxy_env,
        capture_output=True,
        text=True,
    )
    if proxy_generation.returncode != 0:
        print("代理配置生成失败，继续使用直连：")
        print(proxy_generation.stderr or proxy_generation.stdout)
        return None, temp_dir

    config_path = os.path.join(temp_dir, "config.json")
    if not os.path.exists(config_path):
        print("未生成配置文件 config.json，继续使用直连")
        return None, temp_dir

    singbox_bin = os.environ.get("SINGBOX_BIN") or shutil.which("sing-box") or os.path.join(repo_root, "sing-box")
    singbox_bin = resolve_singbox_path(singbox_bin)
    if not singbox_bin or not os.path.exists(singbox_bin):
        print("未找到 sing-box 可执行文件，请确保工作流已下载内核或设置 SINGBOX_BIN")
        return None, temp_dir

    process = subprocess.Popen(
        [singbox_bin, "run", "-c", config_path],
        cwd=temp_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", 8080), timeout=1):
                print("✅ 本地 8080 代理已就绪")
                return process, temp_dir
        except OSError:
            time.sleep(1)

    print("⚠️ 本地 8080 代理未在超时内就绪，继续使用直连")
    stop_local_proxy(process, temp_dir)
    return None, temp_dir


def stop_local_proxy(process, temp_dir):
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            process.kill()
    if temp_dir and os.path.isdir(temp_dir):
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


def _extract_user_info(payload):
    if not isinstance(payload, dict):
        return None

    candidates = []
    if isinstance(payload.get("data"), dict):
        candidates.append(payload["data"])
    candidates.append(payload)

    for item in candidates:
        if not isinstance(item, dict):
            continue

        user_id = None
        for key in ["id", "user_id", "userId", "uid", "uuid"]:
            if item.get(key) not in (None, ""):
                user_id = item.get(key)
                break

        username = None
        for key in ["username", "name", "user_name", "email", "user_email"]:
            if item.get(key) not in (None, ""):
                username = item.get(key)
                break

        if user_id is not None:
            return {"id": user_id, "username": str(username or user_id)}

    if payload.get("success") is True and payload.get("message"):
        return {"id": None, "username": payload.get("message", "")}

    return None


def _login_pending_2fa(session: requests.Session, email, password, headers):
    """重新执行密码登录，建立"待 2FA 验证"的服务端会话。"""
    login_url = f"{BASE_URL}/api/user/login?turnstile={quote(TURNSTILE_TOKEN)}"
    try:
        resp = session.post(login_url, headers=headers, json={"username": email, "password": password}, timeout=20)
    except requests.RequestException as exc:
        return False, {"message": f"网络异常: {exc.__class__.__name__}"}
    try:
        data = resp.json()
    except ValueError:
        data = {}
    pending = (
        data.get("success") is True
        and isinstance(data.get("data"), dict)
        and data["data"].get("require_2fa")
    )
    return pending, data


def _submit_otp_code(session: requests.Session, email, password, otp_secret, payload):
    """提交 2FA 验证码。

    站点真实流程（已抓包验证）：
      1. POST /api/user/login {username, password} -> {"data":{"require_2fa":true},"success":true}
         同时下发 session cookie（保存待验证状态）
      2. POST /api/user/login/2fa {"code": "123456"} -> 成功时 data 即用户信息
    只需要 code 一个字段，凭证由会话承载。验证码错误返回
    {"message":"验证码或备用码不正确","success":false}，且会话在失败后仍然有效。

    返回 (user 或 None, 是否因账户锁定而中止)。
    """
    otp_headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/otp",
    }
    endpoint = f"{BASE_URL}/api/user/login/2fa"

    base_ts = int(time.time())
    # 依次尝试 当前/上一/下一 时间窗，容忍与服务器 30s 内的时钟偏差
    windows = [
        ("当前时间窗", base_ts),
        ("上一时间窗", base_ts - 30),
        ("下一时间窗", base_ts + 30),
    ]

    last_message = ""
    for label, ts in windows:
        code = generate_totp_code(otp_secret, at=ts)
        if not code:
            print("未能生成 2FA 验证码，请检查 OTP_SECRET")
            return None, False

        print(f"📡 提交 2FA | {label} | 验证码 {code} (可与手机验证器比对)")
        try:
            resp = session.post(endpoint, headers=otp_headers, json={"code": code}, timeout=20)
        except requests.RequestException as exc:
            last_message = f"网络异常: {exc.__class__.__name__}"
            print(f"   ↳ {last_message}")
            continue
        try:
            data = resp.json()
        except ValueError:
            data = {}
        print(f"   ↳ 响应 {resp.status_code}: {json.dumps(data, ensure_ascii=False)[:200]}")
        last_message = str(data.get("message") or "")

        if "锁定" in last_message or "稍后再试" in last_message:
            # 站点对连续验证码错误有临时锁定机制，继续重试只会延长锁定
            print("⚠️ 账户因多次验证码错误被临时锁定，停止重试，请稍后运行并核对 OTP_SECRET")
            return None, True

        if data.get("success") is not True:
            # 验证码被拒（验证码或备用码不正确等），换下一个时间窗
            continue

        if isinstance(data.get("data"), dict) and data["data"].get("require_2fa"):
            # 服务端丢失了待验证会话：重新登录建立会话后，用同一验证码重试
            print("   ↳ 服务端仍要求 2FA（会话状态丢失），重新登录后重试")
            pending, redata = _login_pending_2fa(session, email, password, otp_headers)
            if not pending:
                print("   ↳ 重新登录失败:", json.dumps(redata, ensure_ascii=False)[:200])
                return None, False
            try:
                resp = session.post(endpoint, headers=otp_headers, json={"code": code}, timeout=20)
            except requests.RequestException as exc:
                last_message = f"网络异常: {exc.__class__.__name__}"
                print(f"   ↳ {last_message}")
                continue
            try:
                data = resp.json()
            except ValueError:
                data = {}
            print(f"   ↳ 重试响应 {resp.status_code}: {json.dumps(data, ensure_ascii=False)[:200]}")
            last_message = str(data.get("message") or "")
            if data.get("success") is not True:
                continue

        extracted = _extract_user_info(data)
        if extracted and extracted.get("id") not in (None, ""):
            print(f"✅ 2FA 验证成功 | 账户: {mask_username(extracted['username'])}")
            return extracted
        print("2FA 认证成功但未能解析到用户信息，响应体如下:")
        print(json.dumps(data, ensure_ascii=False, indent=2)[:2000])
        return None

    print(f"❌ 2FA 验证码全部被拒绝，最后响应：{last_message}")
    print("   排查建议：核对 OTP_SECRET 是否为该账号两步验证的密钥")
    print("   （若复制的是 otpauth:// 链接，请填其中的 secret 参数值），")
    print("   并用手机验证器当前 6 位数字与上方日志中的验证码比对确认。")
    return None


def login(session: requests.Session, email, password, otp_secret="", use_proxy=False):
    """登录并返回用户信息（id + username），若触发 2FA 则自动提交验证码。"""
    login_url = f"{BASE_URL}/api/user/login?turnstile={quote(TURNSTILE_TOKEN)}"

    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/login",
    }

    payload = {"username": email, "password": password}
    max_attempts = 1 if use_proxy else 3
    resp = None
    for attempt in range(1, 4):
        try:
            resp = session.post(login_url, headers=headers, json=payload, timeout=20)
        except requests.RequestException as exc:
            # 连接类异常（超时/被重置等）与限流无关，无论是否走代理都重试
            print(f"登录请求网络异常 (第 {attempt}/3 次): {exc.__class__.__name__}: {exc}")
            if attempt < 3:
                time.sleep(2)
                continue
            return None, CONN_ERROR
        if resp.status_code != 429:
            break
        if use_proxy:
            print("代理登录限流，立即切换直连")
            break
        wait_seconds = attempt * 2
        print(f"登录请求被限流 (429)，第 {attempt}/{max_attempts} 次重试，等待 {wait_seconds}s...")
        time.sleep(wait_seconds)

    if resp is None or resp.status_code == 429:
        print("登录请求仍然被限流，建议切换直连或降低请求频率")
        return None, 429

    if resp.status_code != 200:
        print("登录请求失败:", resp.status_code)
        return None, resp.status_code

    try:
        data = resp.json()
    except ValueError:
        data = {}

    if data.get("success") is True:
        if isinstance(data.get("data"), dict) and data["data"].get("require_2fa"):
            message = str(data.get("message") or "")
            if not otp_secret:
                print("登录需要 2FA，但未提供 OTP_SECRET")
                return None, 200
            print("🔐 检测到 2FA，正在自动提交验证码...")
            return _submit_otp_code(session, email, password, otp_secret, payload), 200

        extracted = _extract_user_info(data)
        if extracted and extracted.get("id") not in (None, ""):
            print(f"✅ 登录成功 | 账户: {mask_username(extracted['username'])}")
            return extracted, 200
        print("登录成功但未能解析到用户信息，响应体如下:")
        print(json.dumps(data, ensure_ascii=False, indent=2)[:4000])
        return None, 200

    if not otp_secret:
        print("登录失败:", data.get("message", ""))
        return None, 200

    message = str(data.get("message") or "")
    if "2fa" not in message.lower() and "otp" not in message.lower() and "验证码" not in message:
        print("登录失败:", data.get("message", ""))
        return None, 200

    print("🔐 检测到 2FA，正在自动提交验证码...")
    return _submit_otp_code(session, email, password, otp_secret, payload), 200


def get_user_info(session: requests.Session, user_id):
    """获取用户信息，返回 data 字典（包含 quota 等字段）。"""
    url = f"{BASE_URL}/api/user/self"

    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0",
        "Referer": BASE_URL,
        "New-Api-User": str(user_id),
    }

    resp = session.get(url, headers=headers, timeout=20)
    try:
        data = resp.json()
    except ValueError:
        return None
    if data.get("success"):
        return data.get("data", {})
    return None


def checkin(session: requests.Session, user_id):
    """执行签到，返回签到响应的完整 JSON。"""
    url = f"{BASE_URL}/api/user/checkin"

    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Origin": BASE_URL,
        "Referer": BASE_URL,
        "New-Api-User": str(user_id),
    }

    resp = session.post(url, headers=headers, json={}, timeout=20)
    return resp.json()


def quota_to_dollar(quota):
    """将内部 quota 值转换为美元金额（整数）。"""
    return round(quota / QUOTA_PER_UNIT)


def send_notification(message, log_summary=None):
    print("\n" + "=" * 25)
    print(log_summary or message)
    print("=" * 25)

    if TG_BOT_TOKEN and TG_CHAT_ID:
        try:
            tg_url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
            resp = requests.post(
                tg_url,
                json={"chat_id": TG_CHAT_ID, "text": message},
                timeout=10,
            )
            if resp.status_code == 200:
                print("Telegram 通知发送成功")
            else:
                print(f"Telegram 通知发送失败: {resp.status_code} {resp.text}")
        except Exception as exc:
            print("Telegram 通知发送失败:", exc)
    else:
        print("未配置 TG_BOT_TOKEN / TG_CHAT_ID，跳过 Telegram 推送")


def build_summary_message(results):
    if not results:
        return ""

    summary_lines = []
    for index, result in enumerate(results, 1):
        if result["status"] == "success":
            summary_lines.append(
                f"{index}. {result['masked_username']}：签到成功，获得 {result['awarded']}$，余额 {result['balance_after']}$"
            )
        elif result["status"] == "checked":
            summary_lines.append(
                f"{index}. {result['masked_username']}：今日已签到，余额 {result['balance_after']}$"
            )
        else:
            summary_lines.append(
                f"{index}. {result['masked_username']}：签到失败，{result['detail']}"
            )

    return "🎁 iamhc 签到汇总\n\n" + "\n".join(summary_lines)


def run_account(account, account_index, total_accounts):
    email = account.get("email", "")
    password = account.get("password", "")
    if not email or not password:
        print(f"⚠️ 账号 {account_index}/{total_accounts} 缺少邮箱或密码，跳过")
        return

    proxy_process = None
    temp_dir = None
    proxy_ready = False
    try:
        proxy_process, temp_dir = start_local_proxy(account, account_index, total_accounts)
        proxy_ready = proxy_process is not None
        session = build_session(account, proxy_ready=proxy_ready)

        if proxy_ready:
            proxy_ip = fetch_exit_ip({"http": LOCAL_PROXY_URL, "https": LOCAL_PROXY_URL})
            if proxy_ip:
                print(f"🌐 代理出口IP: {mask_ip(proxy_ip)} （已打码，用于排查代理连通性）")
            else:
                print("⚠️ 无法通过代理获取出口IP，代理节点可能不可用或已失效")

        user, status = login(
            session,
            email,
            password,
            account.get("otp_secret") or os.environ.get("OTP_SECRET", ""),
            use_proxy=proxy_ready,
        )
        if not user and status in (429, CONN_ERROR) and proxy_ready:
            print("代理链路异常（限流或连接失败），尝试关代理直连")
            stop_local_proxy(proxy_process, temp_dir)
            proxy_process = None
            proxy_ready = False
            session = build_session(account, proxy_ready=proxy_ready)
            user, status = login(
                session,
                email,
                password,
                account.get("otp_secret") or os.environ.get("OTP_SECRET", ""),
                use_proxy=False,
            )

        if not user:
            if status == CONN_ERROR:
                detail = "登录失败: 代理与直连均无法连接"
            elif status == 429:
                detail = "登录失败: 请求被限流(429)"
            else:
                detail = "登录失败: 凭据或 2FA 验证问题"
            print(f"\n{detail}，无法继续签到")
            return {
                "masked_username": mask_username(email or "未知账号"),
                "status": "failed",
                "detail": detail,
                "balance_before": 0,
                "balance_after": 0,
                "awarded": 0,
            }

        user_id = user["id"]
        username = user.get("username", str(user_id))
        masked_username = mask_username(username)

        info_before = get_user_info(session, user_id)
        if not info_before:
            print("获取用户信息失败")
            return
        balance_before = quota_to_dollar(info_before.get("quota", 0))

        checkin_data = checkin(session, user_id)
        info_after = get_user_info(session, user_id)
        if not info_after:
            print("获取签到后用户信息失败")
            return
        balance_after = quota_to_dollar(info_after.get("quota", 0))

        local_time = time.gmtime(time.time() + 8 * 3600)
        now = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
        success = checkin_data.get("success", False)
        msg = str(checkin_data.get("message", ""))

        if success:
            awarded_data = checkin_data.get("data", {})
            awarded_quota = awarded_data.get("quota_awarded", 0)
            awarded_dollar = quota_to_dollar(awarded_quota) if awarded_quota else (balance_after - balance_before)
            log_summary = f"✅ 签到成功 | 账户: {masked_username}"
            print("\n" + "=" * 25)
            print(log_summary)
            print("=" * 25)
            return {
                "masked_username": masked_username,
                "status": "success",
                "detail": msg,
                "balance_before": balance_before,
                "balance_after": balance_after,
                "awarded": awarded_dollar,
            }
        elif "已签到" in msg or "重复签到" in msg or "今天已签到" in msg:
            log_summary = f"✅ 今日已签到 | 账户: {masked_username}"
            print("\n" + "=" * 25)
            print(log_summary)
            print("=" * 25)
            return {
                "masked_username": masked_username,
                "status": "checked",
                "detail": msg,
                "balance_before": balance_before,
                "balance_after": balance_after,
                "awarded": 0,
            }
        else:
            log_summary = f"❌ 签到失败 | 账户: {masked_username} | {msg}"
            print("\n" + "=" * 25)
            print(log_summary)
            print("=" * 25)
            return {
                "masked_username": masked_username,
                "status": "failed",
                "detail": msg,
                "balance_before": balance_before,
                "balance_after": balance_after,
                "awarded": 0,
            }
    finally:
        if proxy_process is not None:
            stop_local_proxy(proxy_process, temp_dir)


def main():
    accounts = load_accounts_from_env()
    if not accounts:
        print("请先配置账号环境变量，例如 EMAIL_1 / PASSWORD_1 / PROXY_URL_1")
        sys.exit(1)

    print(f"共发现 {len(accounts)} 个账号配置")
    direct_ip = fetch_exit_ip()
    if direct_ip:
        print(f"🏠 本机直连出口IP: {mask_ip(direct_ip)} （对照用：若与代理出口IP相同说明代理未生效）")
    else:
        print("⚠️ 未能获取本机直连出口IP")

    results = []
    for index, account in enumerate(accounts, 1):
        print(f"\n===== 账号 {index}/{len(accounts)} =====")
        try:
            result = run_account(account, index, len(accounts))
        except requests.RequestException as exc:
            print(f"❌ 账号处理被网络异常中断: {exc.__class__.__name__}: {exc}")
            result = {
                "masked_username": mask_username(account.get("email", "") or "未知账号"),
                "status": "failed",
                "detail": f"网络异常: {exc.__class__.__name__}",
                "balance_before": 0,
                "balance_after": 0,
                "awarded": 0,
            }
        except Exception as exc:
            print(f"❌ 账号处理出现未预期异常: {exc.__class__.__name__}: {exc}")
            result = {
                "masked_username": mask_username(account.get("email", "") or "未知账号"),
                "status": "failed",
                "detail": f"异常: {exc.__class__.__name__}",
                "balance_before": 0,
                "balance_after": 0,
                "awarded": 0,
            }
        if result:
            results.append(result)

    summary_message = build_summary_message(results)
    if summary_message:
        send_notification(summary_message, log_summary=f"✅ 签到汇总 | {len(results)} 账号")

    # 全部账号失败时以非零码退出，让 Actions 运行显示为失败便于察觉
    if results and all(r.get("status") == "failed" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
