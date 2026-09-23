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

# 2FA 验证码被拒后的自动重试次数（默认重试 2 次，加上首次共提交 3 次）
try:
    OTP_RETRY_TIMES = max(0, int(os.environ.get("OTP_RETRY_TIMES", "2")))
except ValueError:
    OTP_RETRY_TIMES = 2

# 2FA 提交时依次尝试的时间窗偏移：当前 / 上一 / 下一，容忍与服务器的时钟偏差
OTP_WINDOW_OFFSETS = (0, -30, 30)

# 连接层异常（超时/被重置等）时的返回标记，区别于 HTTP 状态码
CONN_ERROR = "conn_error"
# 2FA 账户锁定标记
LOCKED = "locked"
# 访问令牌无效 / 已失效标记
TOKEN_INVALID = "token_invalid"

# 登录会话复用：从仓库变量 IAMHC_SESSIONS 读取上次会话，运行结束后由工作流
# 用 gh variable set 写回（避免明文写入仓库文件）。
SESSIONS_ENV = "IAMHC_SESSIONS"
SESSIONS_UPDATE_ENV = "IAMHC_SESSIONS_UPDATE"
# 新版 new-api 用刷新令牌 Cookie 承载长会话（旧版为 session Cookie）
REFRESH_COOKIE_NAME = "new_api_refresh"
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


def parse_atoken(raw):
    """解析系统访问令牌配置，支持以下写法（也支持 JSON 对象）：

        id,name,token   -> 推荐写法，例如 12,张三,AbCdEf123...
        id,token        -> 省略用户名
        token           -> 仅令牌（用户 ID 由服务端返回）

    返回 {"id": str, "name": str, "token": str}；没有有效令牌时返回 None。
    """
    raw = (raw or "").strip()
    if not raw:
        return None

    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        token = str(obj.get("token") or obj.get("access_token") or obj.get("atoken") or "").strip()
        token = re.sub(r"^Bearer\s+", "", token, flags=re.I)
        if not token:
            return None
        user_id = obj.get("id", obj.get("user_id", obj.get("uid", "")))
        name = str(obj.get("name") or obj.get("username") or "").strip()
        return {"id": str(user_id).strip() if user_id not in (None, "") else "", "name": name, "token": token}

    parts = [part.strip() for part in re.split(r"[,，]", raw) if part.strip()]
    if not parts:
        return None

    user_id = ""
    name = ""
    if len(parts) >= 3:
        user_id, name = parts[0], parts[1]
        token = ",".join(parts[2:]).strip()
    elif len(parts) == 2:
        # 两段式：以「纯数字」的一段判定为用户 ID
        if parts[0].isdigit():
            user_id, token = parts[0], parts[1]
        else:
            name, token = parts[0], parts[1]
    else:
        token = parts[0]

    token = re.sub(r"^Bearer\s+", "", token.strip(), flags=re.I)
    if not token:
        return None
    return {"id": user_id, "name": name, "token": token}


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
                        "atoken": parse_atoken(
                            item.get("atoken") or item.get("access_token") or item.get("atoken_raw") or ""
                        ),
                    }
                )
        return accounts

    accounts = []
    for index in range(1, 10):
        email = os.environ.get(f"EMAIL_{index}", "").strip()
        password = os.environ.get(f"PASSWORD_{index}", "").strip()
        proxy_url = os.environ.get(f"PROXY_URL_{index}", "").strip()
        otp_secret = os.environ.get(f"OTP_SECRET_{index}", "").strip()
        atoken_raw = first_env(f"ATOKEN_{index}", f"atoken_{index}", f"ACCESS_TOKEN_{index}")
        if any([email, password, proxy_url, otp_secret, atoken_raw]):
            accounts.append(
                {
                    "email": email,
                    "password": password,
                    "proxy_url": proxy_url,
                    "otp_secret": otp_secret,
                    "atoken": parse_atoken(atoken_raw),
                }
            )

    if accounts:
        return accounts

    email = os.environ.get("EMAIL", "").strip()
    password = os.environ.get("PASSWORD", "").strip()
    proxy_url = os.environ.get("PROXY_URL", "").strip()
    otp_secret = os.environ.get("OTP_SECRET", "").strip()
    atoken_raw = first_env("ATOKEN", "atoken", "ACCESS_TOKEN")
    if any([email, password, proxy_url, otp_secret, atoken_raw]):
        return [
            {
                "email": email,
                "password": password,
                "proxy_url": proxy_url,
                "otp_secret": otp_secret,
                "atoken": parse_atoken(atoken_raw),
            }
        ]

    return []


def first_env(*names):
    """按顺序返回第一个非空环境变量值（兼容不同大小写写法）。"""
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


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
    """从环境变量读取上次保存的登录会话：{账号序号: {refresh, user_id, username}}。"""
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


def save_session(session, store, account_index, user=None):
    """登录成功后把刷新令牌记录到 store；user 为 None 时删除该账号旧会话。"""
    if store is None:
        return
    key = str(account_index)
    if user is None:
        store.pop(key, None)
        return
    refresh = session.cookies.get(REFRESH_COOKIE_NAME)
    if not refresh:
        return
    store[key] = {
        "refresh": refresh,
        "user_id": user.get("id"),
        "username": user.get("username") or "",
    }


def reuse_saved_session(session, saved):
    """用保存的刷新令牌换取新的访问令牌，成功返回用户信息，失败返回 None。"""
    if not isinstance(saved, dict):
        return None

    refresh = str(saved.get("refresh") or "").strip()
    if refresh:
        # 新版 new-api：POST /api/user/auth/refresh（需 Origin 校验通过）
        session.cookies.set(REFRESH_COOKIE_NAME, refresh, domain=COOKIE_DOMAIN, path="/")
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Origin": BASE_URL,
            "Referer": f"{BASE_URL}/",
        }
        try:
            resp = session.post(f"{BASE_URL}/api/user/auth/refresh", headers=headers, json={}, timeout=20)
        except requests.RequestException as exc:
            print(f"刷新登录会话网络异常: {exc.__class__.__name__}")
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if data.get("success") is not True:
            return None
        payload = data.get("data") if isinstance(data.get("data"), dict) else {}
        token = payload.get("access_token")
        if token:
            session.headers["Authorization"] = str(token)
        user_data = payload.get("user") if isinstance(payload.get("user"), dict) else {}
        user_id = user_data.get("id") or saved.get("user_id")
        if user_id in (None, ""):
            return None
        return {
            "id": user_id,
            "username": user_data.get("username") or saved.get("username") or str(user_id),
        }

    # 兼容更早版本保存的 session cookie
    legacy_cookie = str(saved.get("cookie") or "").strip()
    if legacy_cookie:
        session.cookies.set(SESSION_COOKIE_NAME, legacy_cookie, domain=COOKIE_DOMAIN, path="/")
        user_data, _status = fetch_self(session, saved.get("user_id"))
        if user_data:
            return {
                "id": user_data.get("id"),
                "username": user_data.get("username") or saved.get("username") or "",
            }
    return None


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
    """从接口响应中解析用户信息。

    兼容多种结构：data.user（新版登录/刷新响应）、data 本身、顶层。
    """
    if not isinstance(payload, dict):
        return None

    candidates = []
    data = payload.get("data")
    if isinstance(data, dict):
        if isinstance(data.get("user"), dict):
            candidates.append(data["user"])
        candidates.append(data)
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
        for key in ["username", "name", "user_name", "display_name", "email", "user_email"]:
            if item.get(key) not in (None, ""):
                username = item.get(key)
                break

        if user_id is not None:
            return {"id": user_id, "username": str(username or user_id)}

    if payload.get("success") is True and payload.get("message"):
        return {"id": None, "username": payload.get("message", "")}

    return None


def _apply_login_session(session, data):
    """登录成功后把访问令牌挂到会话上。

    新版 new-api 的 /api/user/* 接口需要 `Authorization` 头（访问令牌），
    会话 Cookie 只用于刷新令牌换取新的访问令牌。
    """
    if not isinstance(data, dict):
        return
    payload = data.get("data")
    if not isinstance(payload, dict):
        return
    token = payload.get("access_token")
    if token:
        session.headers["Authorization"] = str(token)


def fetch_self(session, user_id_hint=None):
    """GET /api/user/self，返回 (user_data 或 None, status)。

    status: "ok" 成功；"auth" 鉴权失败；CONN_ERROR 连接异常；"error" 其他失败。
    """
    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0",
        "Referer": BASE_URL,
    }
    if user_id_hint not in (None, ""):
        headers["New-Api-User"] = str(user_id_hint)

    try:
        resp = session.get(f"{BASE_URL}/api/user/self", headers=headers, timeout=20)
    except requests.RequestException as exc:
        print(f"获取用户信息网络异常: {exc.__class__.__name__}")
        return None, CONN_ERROR

    try:
        data = resp.json()
    except ValueError:
        return None, "error"

    if resp.status_code == 401 or str(data.get("code") or "") == "AUTH_UNAUTHORIZED":
        return None, "auth"
    if data.get("success") is not True:
        return None, "error"

    user_data = data.get("data")
    if not isinstance(user_data, dict) or user_data.get("id") in (None, ""):
        return None, "error"
    return user_data, "ok"


def _post_login(session, email, password, use_proxy=False):
    """POST /api/user/login，返回 (data 或 None, status)。"""
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
        return resp.json(), 200
    except ValueError:
        return {}, 200


def _login_challenge(data):
    """识别登录响应中的 2FA / 验证流程。

    新版 new-api 返回：
        {"data": {"require_verification": true, "flow_token": "...", "methods": [...]}}
    旧版返回 require_2fa 标记。
    """
    if not isinstance(data, dict):
        return None
    payload = data.get("data")
    if not isinstance(payload, dict):
        return None
    methods = payload.get("methods") if isinstance(payload.get("methods"), list) else []
    if payload.get("require_verification") is True:
        return {
            "kind": "verify",
            "flow_token": str(payload.get("flow_token") or ""),
            "expires_at": payload.get("expires_at"),
            "methods": methods,
        }
    if payload.get("require_2fa") is True:
        return {
            "kind": "legacy_2fa",
            "flow_token": str(payload.get("flow_token") or ""),
            "expires_at": payload.get("expires_at"),
            "methods": methods,
        }
    return None


def _challenge_supports_2fa(challenge):
    """判断验证流程是否提供可用的 2FA 方式。"""
    methods = challenge.get("methods") or []
    if not methods:
        return True  # 未给出方法列表时按 2FA 处理（兼容旧版接口）
    for item in methods:
        if not isinstance(item, dict):
            continue
        if str(item.get("method") or "").lower() in ("2fa", "totp"):
            return item.get("available") is not False
    return False


def _submit_login_code(session, challenge, code):
    """提交 2FA 验证码，返回 (data, status)。

    status: "ok" 成功；"failed" 验证码被拒；"locked" 账户被锁定；
            "expired" 验证流程失效（需重新登录换取新流程）；CONN_ERROR 网络异常；"error" 其他。
    """
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/otp",
    }
    flow_token = str(challenge.get("flow_token") or "").strip()
    if flow_token:
        endpoint = f"{BASE_URL}/api/user/login/verify"
        body = {"flow_token": flow_token, "method": "2fa", "code": code}
    else:
        # 极旧版本只接受 code，凭证由会话承载
        endpoint = f"{BASE_URL}/api/user/login/2fa"
        body = {"code": code}

    try:
        resp = session.post(endpoint, headers=headers, json=body, timeout=20)
    except requests.RequestException as exc:
        print(f"   ↳ 提交验证码网络异常: {exc.__class__.__name__}")
        return None, CONN_ERROR

    try:
        data = resp.json()
    except ValueError:
        data = {}
    print(f"   ↳ 响应 {resp.status_code}: {json.dumps(data, ensure_ascii=False)[:200]}")

    if data.get("success") is True:
        return data, "ok"

    code_field = str(data.get("code") or "")
    message = str(data.get("message") or "")
    lowered = message.lower()
    if code_field == "SECURITY_VERIFICATION_LOCKED" or "锁定" in message or "locked" in lowered:
        return data, "locked"
    if code_field == "AUTH_FLOW_INVALID" or "expired" in lowered or "流程" in message:
        return data, "expired"
    if code_field in ("SECURITY_VERIFICATION_FAILED", "TWOFA_CODE_INVALID") or "验证码" in message or "验证" in message:
        return data, "failed"
    return data, "error"


def _complete_login_verification(session, email, password, otp_secret, challenge, use_proxy):
    """完成 2FA 验证；验证码被拒时自动重试（默认 2 次）。

    每次重试都会重新执行密码登录，换取全新的 flow_token —— 因为验证流程 5 分钟即过期，
    且被消费后无法复用；同时按 当前/上一/下一 时间窗依次生成验证码，容忍时钟偏差。
    """
    total_attempts = 1 + OTP_RETRY_TIMES
    current = challenge
    last_message = ""

    for attempt in range(1, total_attempts + 1):
        offset = OTP_WINDOW_OFFSETS[(attempt - 1) % len(OTP_WINDOW_OFFSETS)]
        if offset == 0:
            window_label = "当前时间窗"
        elif offset < 0:
            window_label = "上一时间窗"
        else:
            window_label = "下一时间窗"

        code = generate_totp_code(otp_secret, at=int(time.time()) + offset)
        if not code:
            print("未能生成 2FA 验证码，请检查 OTP_SECRET")
            return None, 200

        print(f"📡 提交 2FA（第 {attempt}/{total_attempts} 次）| {window_label} | 验证码 {code} (可与手机验证器比对)")
        data, status = _submit_login_code(session, current, code)

        if status == "ok":
            user = _extract_user_info(data)
            if user and user.get("id") not in (None, ""):
                _apply_login_session(session, data)
                print(f"✅ 2FA 验证成功 | 账户: {mask_username(user['username'])}")
                return user, 200
            print("2FA 认证成功但未能解析到用户信息，响应体如下:")
            print(json.dumps(data, ensure_ascii=False, indent=2)[:2000])
            return None, 200

        if status == "locked":
            print("⚠️ 账户因多次验证码错误被临时锁定，停止重试，请稍后运行并核对 OTP_SECRET")
            return None, LOCKED

        if status == CONN_ERROR:
            last_message = "网络异常"
        else:
            last_message = str((data or {}).get("message") or "")

        if attempt >= total_attempts:
            break

        print(f"🔁 2FA 未通过（{last_message or '验证码被拒'}），重新获取验证流程后重试...")
        refreshed, refresh_status = _post_login(session, email, password, use_proxy=use_proxy)
        if refreshed is None:
            print("   ↳ 重新登录失败，停止重试")
            return None, (refresh_status if refresh_status in (CONN_ERROR, 429) else 200)

        new_challenge = _login_challenge(refreshed)
        if new_challenge is None:
            # 极端情况下重新登录直接成功
            user = _extract_user_info(refreshed)
            if user and user.get("id") not in (None, ""):
                _apply_login_session(session, refreshed)
                print(f"✅ 登录成功 | 账户: {mask_username(user['username'])}")
                return user, 200
            print("   ↳ 重新登录未返回验证流程，停止重试")
            return None, 200
        current = new_challenge
        time.sleep(1)

    print(f"❌ 2FA 验证码全部被拒绝（已重试 {OTP_RETRY_TIMES} 次），最后响应：{last_message}")
    print("   排查建议：核对 OTP_SECRET 是否为该账号两步验证的密钥")
    print("   （若复制的是 otpauth:// 链接，请填其中的 secret 参数值），")
    print("   并用手机验证器当前 6 位数字与上方日志中的验证码比对确认。")
    return None, 200


def login(session: requests.Session, email, password, otp_secret="", use_proxy=False):
    """登录并返回用户信息（id + username），若触发 2FA 则自动提交验证码。"""
    data, status = _post_login(session, email, password, use_proxy=use_proxy)
    if data is None:
        return None, status

    if data.get("success") is True:
        challenge = _login_challenge(data)
        if challenge is not None:
            if not _challenge_supports_2fa(challenge):
                print("🔐 登录需要验证，但站点未提供可用的 2FA 方式（可能已锁定或仅支持 Passkey）")
                print(json.dumps(data, ensure_ascii=False, indent=2)[:2000])
                return None, 200
            if not otp_secret:
                print("登录需要 2FA，但未提供 OTP_SECRET（也可改用访问令牌 ATOKEN_x 免 2FA）")
                return None, 200
            print("🔐 检测到 2FA，正在自动提交验证码...")
            return _complete_login_verification(session, email, password, otp_secret, challenge, use_proxy)

        extracted = _extract_user_info(data)
        if extracted and extracted.get("id") not in (None, ""):
            _apply_login_session(session, data)
            print(f"✅ 登录成功 | 账户: {mask_username(extracted['username'])}")
            return extracted, 200
        print("登录成功但未能解析到用户信息，响应体如下:")
        print(json.dumps(data, ensure_ascii=False, indent=2)[:4000])
        return None, 200

    message = str(data.get("message") or "")
    if "锁定" in message:
        print("🔒 账户被临时锁定:", message)
        return None, LOCKED

    if not otp_secret:
        print("登录失败:", message)
        return None, 200

    lowered = message.lower()
    if "2fa" in lowered or "otp" in lowered or "验证码" in message or "验证" in message:
        # 少数旧版部署会直接以错误提示要求验证码，走同一套验证流程
        print("🔐 检测到 2FA，正在自动提交验证码...")
        challenge = {"kind": "legacy_2fa", "flow_token": "", "methods": []}
        return _complete_login_verification(session, email, password, otp_secret, challenge, use_proxy)

    print("登录失败:", message)
    return None, 200


def get_user_info(session: requests.Session, user_id):
    """获取用户信息，返回 data 字典（包含 quota 等字段）。"""
    user_data, _status = fetch_self(session, user_id)
    return user_data


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


def _fail(masked_username, detail):
    return {
        "masked_username": masked_username,
        "status": "failed",
        "detail": detail,
        "balance_before": 0,
        "balance_after": 0,
        "awarded": 0,
    }


def do_checkin(session, user):
    """登录成功后的签到与余额查询，返回结果字典。"""
    user_id = user["id"]
    username = user.get("username", str(user_id))
    masked_username = mask_username(username)

    info_before = get_user_info(session, user_id)
    if not info_before:
        print("获取用户信息失败")
        return _fail(masked_username, "获取用户信息失败")
    balance_before = quota_to_dollar(info_before.get("quota", 0))

    checkin_data = checkin(session, user_id)
    info_after = get_user_info(session, user_id)
    if not info_after:
        print("获取签到后用户信息失败")
        return _fail(masked_username, "获取签到后用户信息失败")
    balance_after = quota_to_dollar(info_after.get("quota", 0))

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
    if "已签到" in msg or "重复签到" in msg or "今天已签到" in msg:
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
    if "turnstile" in msg.lower():
        print("⚠️ 站点对签到开启了 Turnstile 人机验证，脚本无法自动通过，请在站点后台关闭或改用访问令牌")
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


def run_token_checkin(session, account):
    """使用系统访问令牌（ATOKEN_x）直接完成签到，返回 (result 或 None, status)。

    令牌模式无需账号密码、无需 2FA：把令牌放进 `Authorization` 头，
    服务端据此识别用户；配置里的用户 ID / 用户名仅作为兜底与展示。
    """
    token_info = account.get("atoken") or {}
    token = token_info.get("token") or ""
    if not token:
        return None, TOKEN_INVALID

    session.headers["Authorization"] = token

    user_data, status = fetch_self(session)
    if status == "auth" and token_info.get("id"):
        # 兼容仍要求 New-Api-User 的旧版部署
        user_data, status = fetch_self(session, token_info["id"])

    if user_data is None:
        if status == "auth":
            print("❌ 访问令牌无效或已失效，请到站点「个人设置 → 系统访问令牌」重新生成")
            return None, TOKEN_INVALID
        if status == CONN_ERROR:
            return None, CONN_ERROR
        print("❌ 访问令牌可用但获取用户信息失败")
        return None, "failed"

    user_id = user_data.get("id")
    username = user_data.get("username") or token_info.get("name") or str(user_id)
    print(f"🔑 访问令牌登录成功 | 账户: {mask_username(username)} (ID {user_id})")
    return do_checkin(session, {"id": user_id, "username": username}), "ok"


def run_account(account, account_index, total_accounts, saved_session=None, session_store=None):
    email = account.get("email", "")
    password = account.get("password", "")
    atoken = account.get("atoken") or {}
    has_token = bool(atoken.get("token"))
    has_password = bool(email and password)

    if not has_token and not has_password:
        print(f"⚠️ 账号 {account_index}/{total_accounts} 缺少访问令牌或邮箱密码，跳过")
        return None

    proxy_state = {"process": None, "temp_dir": None}

    def cleanup_proxy():
        if proxy_state["process"] is not None:
            stop_local_proxy(proxy_state["process"], proxy_state["temp_dir"])
        proxy_state["process"] = None
        proxy_state["temp_dir"] = None

    def attempt(reuse_session):
        """执行一轮 起代理→(令牌/复用会话/登录)→签到，返回 (result 或 None, status)。"""
        try:
            proxy_state["process"], proxy_state["temp_dir"] = start_local_proxy(
                account, account_index, total_accounts
            )
            proxy_ready = proxy_state["process"] is not None
            session = build_session(account, proxy_ready=proxy_ready)

            if proxy_ready:
                proxy_ip = fetch_exit_ip({"http": LOCAL_PROXY_URL, "https": LOCAL_PROXY_URL})
                if proxy_ip:
                    print(f"🌐 代理出口IP: {mask_ip(proxy_ip)} （已打码，用于排查代理连通性）")
                else:
                    print("⚠️ 无法通过代理获取出口IP，代理节点可能不可用或已失效")

            # 1) 优先使用访问令牌：免登录、免 2FA，最稳定
            if has_token:
                result, status = run_token_checkin(session, account)
                if result is not None:
                    return result, "ok"
                if not has_password:
                    return None, status
                print("⚠️ 访问令牌不可用，改用账号密码登录完成签到")

            otp_secret = account.get("otp_secret") or os.environ.get("OTP_SECRET", "")
            user = None

            # 2) 复用上次保存的登录会话，避免每次登录和 2FA
            if reuse_session and saved_session:
                reused = reuse_saved_session(session, saved_session)
                if reused:
                    info, _status = fetch_self(session, reused.get("id"))
                    if info:
                        user = {
                            "id": info.get("id"),
                            "username": info.get("username") or reused.get("username") or "",
                        }
                        print(f"♻️ 复用已保存登录会话，跳过登录与 2FA | 账户: {mask_username(user['username'])}")
                    else:
                        print("已保存会话已失效，转入正常登录")
                        save_session(None, session_store, account_index)
                else:
                    print("已保存会话已失效，转入正常登录")
                    save_session(None, session_store, account_index)

            # 3) 完整登录（可能触发 2FA）
            if user is None:
                user, login_status = login(session, email, password, otp_secret, use_proxy=proxy_ready)
                if not user and login_status in (429, CONN_ERROR) and proxy_ready:
                    print("代理链路异常（限流或连接失败），尝试关代理直连")
                    cleanup_proxy()
                    session = build_session(account, proxy_ready=False)
                    user, login_status = login(session, email, password, otp_secret, use_proxy=False)
                if not user:
                    save_session(None, session_store, account_index)
                    return None, (login_status if login_status in (LOCKED, CONN_ERROR) else "failed")

            # 登录成功，记录当前会话供下次复用
            save_session(session, session_store, account_index, user)
            return do_checkin(session, user), "ok"
        finally:
            cleanup_proxy()

    try:
        result, status = attempt(reuse_session=True)

        # 4) 2FA 锁定：保持本次运行等待 16 分钟后再尝试一次
        if status == LOCKED:
            wait_minutes = 16
            until = time.strftime("%H:%M:%S", time.gmtime(time.time() + wait_minutes * 60 + 8 * 3600))
            print(f"\n⏳ 账户被 2FA 临时锁定，保持运行 {wait_minutes} 分钟后自动重试一次（约北京时间 {until}）")
            time.sleep(wait_minutes * 60)
            print("锁定等待结束，重新尝试登录")
            result, status = attempt(reuse_session=False)

        if result is not None:
            return result

        if status == CONN_ERROR:
            detail = "登录失败: 代理与直连均无法连接"
        elif status == LOCKED:
            detail = "登录失败: 2FA 锁定，重试仍未成功（请核对 OTP_SECRET）"
        elif status == TOKEN_INVALID:
            detail = "登录失败: 访问令牌无效，请重新生成 ATOKEN_x"
        elif status == 429:
            detail = "登录失败: 请求被限流(429)"
        else:
            detail = "登录失败: 凭据或 2FA 验证问题"
        print(f"\n{detail}，无法继续签到")
        return _fail(mask_username(email or (atoken.get("name") or "未知账号")), detail)
    finally:
        cleanup_proxy()


def main():
    accounts = load_accounts_from_env()
    if not accounts:
        print("请先配置账号环境变量，例如 ATOKEN_1（推荐）或 EMAIL_1 / PASSWORD_1 / OTP_SECRET_1")
        sys.exit(1)

    print(f"共发现 {len(accounts)} 个账号配置")
    token_count = sum(1 for item in accounts if (item.get("atoken") or {}).get("token"))
    if token_count:
        print(f"🔑 其中 {token_count} 个账号配置了访问令牌（ATOKEN_x），将优先使用令牌签到")
    direct_ip = fetch_exit_ip()
    if direct_ip:
        print(f"🏠 本机直连出口IP: {mask_ip(direct_ip)} （对照用：若与代理出口IP相同说明代理未生效）")
    else:
        print("⚠️ 未能获取本机直连出口IP")

    session_store = load_session_store()
    if session_store:
        print(f"🍪 已加载 {len(session_store)} 个上次保存的登录会话，将优先复用免登录")

    results = []
    for index, account in enumerate(accounts, 1):
        print(f"\n===== 账号 {index}/{len(accounts)} =====")
        try:
            result = run_account(
                account,
                index,
                len(accounts),
                saved_session=session_store.get(str(index)),
                session_store=session_store,
            )
        except requests.RequestException as exc:
            print(f"❌ 账号处理被网络异常中断: {exc.__class__.__name__}: {exc}")
            result = _fail(mask_username(account.get("email", "") or "未知账号"), f"网络异常: {exc.__class__.__name__}")
        except Exception as exc:
            print(f"❌ 账号处理出现未预期异常: {exc.__class__.__name__}: {exc}")
            result = _fail(mask_username(account.get("email", "") or "未知账号"), f"异常: {exc.__class__.__name__}")
        if result:
            results.append(result)
        # 每个账号处理完即写回最新会话，供工作流用 gh variable set 持久化
        export_session_store(session_store)

    summary_message = build_summary_message(results)
    if summary_message:
        send_notification(summary_message, log_summary=f"✅ 签到汇总 | {len(results)} 账号")

    # 全部账号失败时以非零码退出，让 Actions 运行显示为失败便于察觉
    if results and all(r.get("status") == "failed" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
