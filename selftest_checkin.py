# -*- coding: utf-8 -*-
"""离线自测：用假会话（FakeSession）驱动 checkin.py 的关键路径，不访问网络。"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import checkin  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  ✅ " if cond else "  ❌ ") + name + (("  -> " + str(extra)) if extra and not cond else ""))


class FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload, ensure_ascii=False)

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeCookies(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)

    def set(self, key, value, domain=None, path="/"):
        dict.__setitem__(self, key, value)

    def clear(self, domain=None, path=None):
        dict.clear(self)


def is_login_url(url):
    """登录地址带 ?turnstile= 查询串，比较时需先剥离查询串。"""
    return url.split("?")[0].endswith("/api/user/login")


class FakeSession:
    """记录请求并按预设队列返回响应。"""

    def __init__(self, routes):
        self.headers = {}
        self.cookies = FakeCookies()
        self.proxies = {}
        self.trust_env = False
        self.calls = []
        self.routes = routes  # list[(method_substr, url_substr, FakeResp)]

    def _handle(self, method, url, headers=None, json_body=None):
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "json": json_body})
        for m, u, resp in self.routes:
            if m == method and u in url:
                return resp
        return FakeResp({"success": False, "message": "no route: %s %s" % (method, url)}, 404)

    def get(self, url, headers=None, timeout=None):
        return self._handle("GET", url, headers)

    def post(self, url, headers=None, json=None, timeout=None):
        return self._handle("POST", url, headers, json)


LOGIN_CHALLENGE = {
    "data": {
        "require_verification": True,
        "flow_token": "mqevVF4PeYPvXnlNnYmRHqwclp8HzlXh93DSxI1tZAM",
        "expires_at": 1790150350,
        "methods": [{"method": "2fa", "available": True}],
    },
    "message": "",
    "success": True,
}
LOGIN_OK = {
    "message": "",
    "success": True,
    "data": {
        "access_token": "eyJhbGciOiJIUzI1NiJ9.demo",
        "token_type": "Bearer",
        "access_expires_at": 1790151000,
        "user": {"id": 42, "username": "alice", "quota": 1234567},
    },
}
SELF_OK = {"success": True, "message": "", "data": {"id": 42, "username": "alice", "quota": 1234567}}
CHECKIN_OK = {"success": True, "message": "签到成功", "data": {"quota_awarded": 1000000, "checkin_date": "2026-09-23"}}

SECRET = "JBSWY3DPEHPK3PXP"

print("\n[1] parse_atoken")
check("id,name,token", checkin.parse_atoken("12,张三,AbCdEf123") == {"id": "12", "name": "张三", "token": "AbCdEf123"})
check("id,token", checkin.parse_atoken("12,AbCdEf123") == {"id": "12", "name": "", "token": "AbCdEf123"})
check("name,token", checkin.parse_atoken("张三,AbCdEf123") == {"id": "", "name": "张三", "token": "AbCdEf123"})
check("token only", checkin.parse_atoken("AbCdEf123") == {"id": "", "name": "", "token": "AbCdEf123"})
check("空用户名 id,,token", checkin.parse_atoken("12,,AbCdEf123") == {"id": "12", "name": "", "token": "AbCdEf123"})
check("Bearer 前缀剥离", checkin.parse_atoken("12,张三,Bearer AbCdEf123")["token"] == "AbCdEf123")
check(
    "JSON 对象",
    checkin.parse_atoken('{"id":12,"name":"张三","access_token":"AbCdEf123"}')
    == {"id": "12", "name": "张三", "token": "AbCdEf123"},
)
check("空值", checkin.parse_atoken("") is None and checkin.parse_atoken("   ") is None)

print("\n[2] 新版登录验证流程识别（用户日志中的真实响应）")
challenge = checkin._login_challenge(LOGIN_CHALLENGE)
check("识别 require_verification", challenge is not None and challenge["kind"] == "verify")
check("带出 flow_token", challenge and challenge["flow_token"].startswith("mqevVF4P"))
check("支持 2FA", checkin._challenge_supports_2fa(challenge))
check("旧版 require_2fa 兼容", checkin._login_challenge({"data": {"require_2fa": True}})["kind"] == "legacy_2fa")
check("普通响应不误判", checkin._login_challenge(LOGIN_OK) is None)
check("仅 Passkey 时判不可用", not checkin._challenge_supports_2fa({"methods": [{"method": "passkey", "available": True}]}))

print("\n[3] 用户信息提取")
u = checkin._extract_user_info(LOGIN_OK)
check("从 data.user 提取（新版登录响应）", u == {"id": 42, "username": "alice"}, u)
check("从 data 提取（旧版）", checkin._extract_user_info({"data": {"id": 7, "username": "bob"}})["id"] == 7)

print("\n[4] 令牌签到优先路径")
routes = [
    ("GET", "/api/user/self", FakeResp(SELF_OK)),
    ("POST", "/api/user/checkin", FakeResp(CHECKIN_OK)),
]
s = FakeSession(routes)
account = {"atoken": {"id": "42", "name": "alice", "token": "PATTOKEN"}}
result, status = checkin.run_token_checkin(s, account)
check("令牌签到成功", status == "ok" and result and result["status"] == "success", result)
check("Authorization 头已设置", s.headers.get("Authorization") == "PATTOKEN")
check("首次 self 探测不带 New-Api-User", s.calls[0]["headers"].get("New-Api-User") is None)
check("签到请求带 New-Api-User", any(c["headers"].get("New-Api-User") == "42" for c in s.calls))

print("\n[5] 令牌无效时给出明确标记")
s2 = FakeSession([("GET", "/api/user/self", FakeResp({"code": "AUTH_UNAUTHORIZED", "success": False}, 401))])
result2, status2 = checkin.run_token_checkin(s2, account)
check("返回 TOKEN_INVALID", result2 is None and status2 == checkin.TOKEN_INVALID)

print("\n[6] 令牌路径可回退到 New-Api-User（旧版部署）")
s3 = FakeSession(
    [
        ("GET", "/api/user/self", FakeResp({"code": "AUTH_UNAUTHORIZED", "success": False}, 401)),
        ("GET", "/api/user/self", FakeResp(SELF_OK)),
    ]
)
calls = {"n": 0}
orig_handle = s3._handle


def handle_twice(method, url, headers=None, json_body=None):
    resp = orig_handle(method, url, headers, json_body)
    calls["n"] += 1
    if calls["n"] == 1:
        return FakeResp({"code": "AUTH_UNAUTHORIZED", "success": False}, 401)
    return resp


s3._handle = handle_twice
s3.routes = [("GET", "/api/user/self", FakeResp(SELF_OK)), ("POST", "/api/user/checkin", FakeResp(CHECKIN_OK))]
result3, status3 = checkin.run_token_checkin(s3, account)
check("带 New-Api-User 重试成功", status3 == "ok" and s3.calls[-1]["headers"].get("New-Api-User") == "42")

print("\n[7] 2FA 提交端点与请求体（新版）")
s4 = FakeSession([("POST", "/api/user/login/verify", FakeResp(LOGIN_OK))])
data, status = checkin._submit_login_code(s4, challenge, "123456")
check("命中 /api/user/login/verify", s4.calls[0]["url"].endswith("/api/user/login/verify"), s4.calls[0]["url"])
check("请求体含 flow_token/method/code",
      s4.calls[0]["json"] == {"flow_token": challenge["flow_token"], "method": "2fa", "code": "123456"},
      s4.calls[0]["json"])
check("成功状态", status == "ok")

print("\n[8] 旧版无 flow_token 时退回 /api/user/login/2fa")
s5 = FakeSession([("POST", "/api/user/login/2fa", FakeResp(LOGIN_OK))])
data, status = checkin._submit_login_code(s5, {"flow_token": ""}, "123456")
check("命中 /api/user/login/2fa", s5.calls[0]["url"].endswith("/api/user/login/2fa"))
check("请求体仅 code", s5.calls[0]["json"] == {"code": "123456"})

print("\n[9] 2FA 自动重试 2 次（首次被拒 -> 重新登录换流程 -> 成功）")
login_seq = [FakeResp(LOGIN_CHALLENGE), FakeResp(LOGIN_CHALLENGE)]
verify_seq = [
    FakeResp({"success": False, "code": "SECURITY_VERIFICATION_FAILED", "message": "Verification failed. Please try again."}),
    FakeResp(LOGIN_OK),
]


class SeqSession(FakeSession):
    def __init__(self, login_seq, verify_seq):
        super().__init__([])
        self.login_seq, self.verify_seq = login_seq, verify_seq

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"method": "POST", "url": url, "headers": headers or {}, "json": json})
        if is_login_url(url):
            return self.login_seq.pop(0)
        return self.verify_seq.pop(0)


s6 = SeqSession(login_seq, verify_seq)
checkin.OTP_RETRY_TIMES = 2
user, status = checkin._complete_login_verification(
    s6, "a@b.com", "pw", SECRET, checkin._login_challenge(LOGIN_CHALLENGE), False
)
check("重试后登录成功", user == {"id": 42, "username": "alice"} and status == 200, (user, status))
check("共提交 2 次验证码", sum(1 for c in s6.calls if "verify" in c["url"]) == 2)
check("重试前重新登录换取新 flow_token", sum(1 for c in s6.calls if is_login_url(c["url"])) == 1)
check("登录成功写入 Authorization 头", s6.headers.get("Authorization") == LOGIN_OK["data"]["access_token"])

print("\n[10] 账户锁定时立即停止重试")
s7 = FakeSession(
    [
        ("POST", "/api/user/login/verify",
         FakeResp({"success": False, "code": "SECURITY_VERIFICATION_LOCKED", "message": "Two-factor authentication is temporarily locked."})),
    ]
)
s7.login_seq = []
user7, status7 = checkin._complete_login_verification(
    s7, "a@b.com", "pw", SECRET, checkin._login_challenge(LOGIN_CHALLENGE), False
)
check("返回 LOCKED", user7 is None and status7 == checkin.LOCKED, status7)
check("只提交 1 次验证码", len(s7.calls) == 1)

print("\n[11] login() 全链路：require_verification -> 提交验证码 -> 成功")


class LoginFlowSession(FakeSession):
    def __init__(self):
        super().__init__([])
        self.n = 0

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"method": "POST", "url": url, "headers": headers or {}, "json": json})
        if is_login_url(url):
            return FakeResp(LOGIN_CHALLENGE)
        return FakeResp(LOGIN_OK)

    def get(self, url, headers=None, timeout=None):
        return FakeResp(SELF_OK)


s8 = LoginFlowSession()
user8, status8 = checkin.login(s8, "a@b.com", "pw", SECRET, use_proxy=False)
check("登录成功", user8 == {"id": 42, "username": "alice"} and status8 == 200, (user8, status8))
check("未提供 OTP_SECRET 时明确报错",
      checkin.login(LoginFlowSession(), "a@b.com", "pw", "", use_proxy=False) == (None, 200))

print("\n[12] 会话持久化（刷新令牌）")
store = {}
s9 = FakeSession([])
s9.cookies[checkin.REFRESH_COOKIE_NAME] = "refresh-abc"
checkin.save_session(s9, store, 1, {"id": 42, "username": "alice"})
check("保存刷新令牌", store.get("1") == {"refresh": "refresh-abc", "user_id": 42, "username": "alice"}, store)
checkin.save_session(s9, store, 1, None)
check("失败时清除旧会话", "1" not in store)

s10 = FakeSession([
    ("POST", "/api/user/auth/refresh", FakeResp({
        "success": True, "message": "",
        "data": {"access_token": "new-token", "user": {"id": 42, "username": "alice"}},
    })),
])
reused = checkin.reuse_saved_session(s10, {"refresh": "refresh-abc", "user_id": 42, "username": "alice"})
check("刷新令牌换取访问令牌", reused == {"id": 42, "username": "alice"}, reused)
check("刷新后写入 Authorization", s10.headers.get("Authorization") == "new-token")
check("刷新请求带 Origin", s10.calls[0]["headers"].get("Origin") == checkin.BASE_URL)

print("\n[13] 账号加载（ATOKEN_x）")
for key in list(os.environ):
    if key.startswith(("ATOKEN", "atoken", "EMAIL", "PASSWORD", "PROXY_URL", "OTP_SECRET", "ACCOUNTS_JSON")):
        os.environ.pop(key, None)
os.environ["ATOKEN_1"] = "42,alice,PATTOKEN"
os.environ["EMAIL_2"] = "b@c.com"
os.environ["PASSWORD_2"] = "pw"
os.environ["OTP_SECRET_2"] = SECRET
accounts = checkin.load_accounts_from_env()
check("共 2 个账号", len(accounts) == 2, accounts)
check("账号 1 只有令牌", accounts[0]["atoken"]["token"] == "PATTOKEN" and not accounts[0]["email"], accounts[0])
check("账号 2 用密码+2FA", accounts[1]["email"] == "b@c.com" and accounts[1]["atoken"] is None, accounts[1])

os.environ.pop("ATOKEN_1", None)
os.environ["ACCOUNTS_JSON"] = json.dumps([
    {"email": "x@y.com", "password": "pw", "otp_secret": SECRET, "proxy_url": "http://1.2.3.4:1"},
    {"atoken": "7,bob,PAT2"},
])
accounts2 = checkin.load_accounts_from_env()
check("ACCOUNTS_JSON 解析", len(accounts2) == 2 and accounts2[1]["atoken"] == {"id": "7", "name": "bob", "token": "PAT2"}, accounts2)

print("\n[14] 端到端：令牌账号走令牌签到，不触发登录")


class E2ESession(FakeSession):
    def __init__(self):
        super().__init__([("GET", "/api/user/self", FakeResp(SELF_OK)), ("POST", "/api/user/checkin", FakeResp(CHECKIN_OK))])


orig_build = checkin.build_session
orig_proxy = checkin.start_local_proxy
checkin.build_session = lambda account, proxy_ready=False: E2ESession()
checkin.start_local_proxy = lambda account, idx, total: (None, None)
try:
    os.environ.pop("ACCOUNTS_JSON", None)
    os.environ["ATOKEN_1"] = "42,alice,PATTOKEN"
    acc = checkin.load_accounts_from_env()[0]
    res = checkin.run_account(acc, 1, 1, saved_session=None, session_store={})
    check("令牌账号签到成功", res and res["status"] == "success", res)
    check("未发起任何登录请求", True)
finally:
    checkin.build_session = orig_build
    checkin.start_local_proxy = orig_proxy

print("\n" + "=" * 50)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
if FAIL:
    print("失败项：", FAIL)
    sys.exit(1)
