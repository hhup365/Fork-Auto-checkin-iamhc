#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import hmac
import hashlib
from urllib.parse import quote

import requests

TG_CHAT_ID = os.environ.get("TG_CHAT_ID") or ""
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN") or ""

BASE_URL = "https://api.hcnsec.cn"
QUOTA_PER_UNIT = 500000
TURNSTILE_TOKEN = ""
LOCAL_PROXY_URL = os.environ.get("LOCAL_PROXY_URL", "http://127.0.0.1:8080").strip()
OTP_SECRET = os.environ.get("OTP_SECRET", "").strip()


def generate_totp_code(secret: str, digits: int = 6, period: int = 30):
    secret = (secret or OTP_SECRET or "").strip()
    if not secret:
        return ""
    try:
        secret_bytes = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    except Exception:
        secret_bytes = secret.encode("utf-8")

    timestamp = int(time.time()) // period
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


def login(session: requests.Session, email, password, otp_secret=""):
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
    resp = session.post(login_url, headers=headers, json=payload, timeout=20)

    if resp.status_code != 200:
        print("登录请求失败:", resp.status_code)
        return None

    try:
        data = resp.json()
    except ValueError:
        data = {}

    if data.get("success") is True:
        extracted = _extract_user_info(data)
        if extracted and extracted.get("id") not in (None, ""):
            print(f"✅ 登录成功 | 账户: {extracted['username']} | ID: {extracted['id']}")
            return extracted
        print("登录成功但未能解析到用户信息，响应体如下:")
        print(json.dumps(data, ensure_ascii=False, indent=2)[:4000])
        return None

    if not otp_secret:
        print("登录失败:", data.get("message", ""))
        return None

    message = str(data.get("message") or "")
    if "2fa" not in message.lower() and "otp" not in message.lower() and "验证码" not in message:
        print("登录失败:", data.get("message", ""))
        return None

    code = generate_totp_code(otp_secret)
    if not code:
        print("未能生成 2FA 验证码，请检查 OTP_SECRET")
        return None

    print("🔐 检测到 2FA，正在自动提交验证码...")
    otp_headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/otp",
    }

    otp_payload_candidates = [
        {"username": email, "password": password, "otp": code},
        {"username": email, "password": password, "code": code},
        {"username": email, "password": password, "totp": code},
        {"username": email, "password": password, "token": code},
        {"otp": code},
        {"code": code},
        {"totp": code},
        {"token": code},
    ]

    for candidate in otp_payload_candidates:
        otp_resp = session.post(
            f"{BASE_URL}/api/user/login?turnstile={quote(TURNSTILE_TOKEN)}",
            headers=otp_headers,
            json={**payload, **candidate},
            timeout=20,
        )
        try:
            otp_data = otp_resp.json()
        except ValueError:
            otp_data = {}
        if otp_data.get("success") is True:
            extracted = _extract_user_info(otp_data)
            if extracted and extracted.get("id") not in (None, ""):
                print(f"✅ 2FA 验证成功 | 账户: {extracted['username']} | ID: {extracted['id']}")
                return extracted
            print("2FA 认证成功但未能解析到用户信息，响应体如下:")
            print(json.dumps(otp_data, ensure_ascii=False, indent=2)[:4000])
            return None
        if otp_resp.status_code == 200 and otp_data.get("message"):
            print("2FA 提交响应:", otp_data.get("message"))

    print("2FA 验证失败，登录流程未完成")
    return None


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
    data = resp.json()
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


def send_notification(message):
    print("\n" + "=" * 25)
    print(message)
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

        user = login(session, email, password, account.get("otp_secret") or os.environ.get("OTP_SECRET", ""))
        if not user:
            print("\n登录失败，无法继续签到")
            return

        user_id = user["id"]
        username = user.get("username", str(user_id))

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
            print(f"✅ 签到成功 | 获得: {awarded_dollar}$")
            message = (
                f"🎁 iamhc 签到通知\n\n"
                f"✅ 签到成功,本次签到获得{awarded_dollar}$\n"
                f"👤 登录账户: {username}\n"
                f"💰 昨日余额: {balance_before}$\n"
                f"💰 当前余额: {balance_after}$\n"
                f"⏱️ 签到时间: {now}"
            )
        elif "已签到" in msg or "重复签到" in msg or "今天已签到" in msg:
            print(f"✅ 今日已签到 | 当前余额: {balance_after}$")
            message = (
                f"🎁 iamhc 签到通知\n\n"
                f"✅ 今日你已经签到过了！\n"
                f"👤 登录账户: {username}\n"
                f"💰 昨日余额: {balance_before}$\n"
                f"💰 当前余额: {balance_after}$\n"
                f"⏱️ 签到时间: {now}"
            )
        else:
            print(f"❌ 签到失败 | {msg}")
            message = (
                f"🎁 iamhc 签到通知\n\n"
                f"❌ 签到失败: {msg}\n"
                f"👤 登录账户: {username}\n"
                f"💰 昨日余额: {balance_before}$\n"
                f"💰 当前余额: {balance_after}$\n"
                f"⏱️ 签到时间: {now}"
            )

        send_notification(message)
    finally:
        if proxy_process is not None:
            stop_local_proxy(proxy_process, temp_dir)


def main():
    accounts = load_accounts_from_env()
    if not accounts:
        print("请先配置账号环境变量，例如 EMAIL_1 / PASSWORD_1 / PROXY_URL_1")
        sys.exit(1)

    print(f"共发现 {len(accounts)} 个账号配置")
    for index, account in enumerate(accounts, 1):
        print(f"\n===== 账号 {index}/{len(accounts)} =====")
        run_account(account, index, len(accounts))


if __name__ == "__main__":
    main()
