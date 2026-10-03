"""
森系记账本 - 云端后端
- POST /api/register  注册账号（可携带本月默认数据，密码加盐 SHA-256 哈希存储）
- POST /api/login     登录返回 token
- GET  /api/health    健康检查（前端用它判断"这个地址真的有后端"）
- GET  /api/data      读取当前用户数据（需 token）
- PUT  /api/data      写入当前用户数据（需 token）
- 数据持久化到 data/ 目录下的 JSON 文件；同时可直接托管 static/ 下的前端（同源，无需跨域）

同步原理：账号 + 密码 → token；前端把 token 放在 X-Auth-Token 头里，
换任何设备登录同一账号，GET /api/data 就能把账本取回来。

用户数据结构（v2）：
{
  "version": 2,
  "defaults":    {"eat": 600, "snack": 100, "want": 520, "misc": 80},  # 注册时的默认数据
  "monthKey":    "2026-09",     # 当前记账月份
  "lastReset":   1789000000000, # 上次「每月 1 号 04:00」重置时间
  "lastEatDate": "2026-09-10",  # 上次「每日 0 点」刷新今日消费的日期
  "budgets":     {"eat": 600, "snack": 100, "want": 520, "misc": 80},  # 本月基准预算
  "eatDaily":    {"2026-09-10": {"b": 10, "l": 15, "d": 20}},          # 吃饭按日明细
  "snackRecords":[{"id": "..", "name": "薯片", "amount": 8.5, "date": "2026-09-10"}],
  "wantRecords": [{"id": "..", "name": "奶茶", "amount": 18, "date": "2026-09-10", "tag": "🧋"}],
  "misc":        {"shower": 5, "water": 3, "washer": 2},
  "archives":    [{"month": "2026-08", ...}]
}
"""
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "users.json"
DATA_DIR.mkdir(exist_ok=True)
BOOT_TIME = time.time()

# 前端默认放在 static/；如果放到别处，用 STATIC_DIR 环境变量指过去
STATIC_DIR = Path(os.environ.get("STATIC_DIR", BASE_DIR / "static"))

# 四个单元的兜底默认值
FALLBACK_DEFAULTS = {"eat": 600.0, "snack": 100.0, "want": 520.0, "misc": 80.0}

app = FastAPI(title="森系记账本", version="0.2.0")

# 允许前端部署在别的域名（静态托管）时跨域调用 /api/*。
# 用自定义头 X-Auth-Token 传 token，不依赖 Cookie，所以不需要 allow_credentials。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)

@app.middleware("http")
async def no_cache_api(request: Request, call_next):
    """API 响应禁止任何缓存（含 CDN），避免 401 被缓存后一直返回"""
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# ---------- 数据持久化 ----------
def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")

def user_data_path(username: str) -> Path:
    safe = "".join(c for c in username if c.isalnum() or c in "_-")
    if not safe:
        safe = hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]
    return DATA_DIR / f"user_{safe}.json"

def hash_pwd(pwd: str, salt: str) -> str:
    return hashlib.sha256((salt + pwd).encode("utf-8")).hexdigest()

def normalize_defaults(raw) -> dict:
    out = dict(FALLBACK_DEFAULTS)
    if isinstance(raw, dict):
        for k in out:
            try:
                v = float(raw.get(k, out[k]))
                if v >= 0:
                    out[k] = v
            except (TypeError, ValueError):
                pass
    return out

def new_book(defaults: dict) -> dict:
    """按注册时的默认数据生成一本新账本"""
    lt = time.localtime()
    month = "%04d-%02d" % (lt.tm_year, lt.tm_mon)
    return {
        "version": 2,
        "defaults": defaults,
        "monthKey": month,
        "lastReset": int(time.time() * 1000),
        "lastEatDate": "%s-%02d" % (month, lt.tm_mday),
        "budgets": dict(defaults),
        "eatDaily": {},
        "snackRecords": [],
        "wantRecords": [],
        "misc": {"shower": 0, "water": 0, "washer": 0},
        "archives": [],
    }

# ---------- 鉴权 ----------
# 一个账号可以同时在多台设备上登录：每次登录签发一个新 token 并保留旧的，
# 这样手机登录不会把电脑踢下线。只保留最近 MAX_TOKENS 个有效 token。
MAX_TOKENS = 10

def tokens_of(info: dict) -> list:
    out = []
    t = info.get("token")
    if t:
        out.append(t)
    for t in (info.get("tokens") or []):
        if t and t not in out:
            out.append(t)
    return out

def issue_token(user: dict) -> str:
    tok = secrets.token_urlsafe(24)
    lst = list(user.get("tokens") or [])
    lst.append(tok)
    user["tokens"] = lst[-MAX_TOKENS:]
    user["token"] = tok          # 保留单 token 字段，兼容旧数据/旧前端
    return tok

def get_username_from_token(token: str) -> str | None:
    if not token:
        return None
    users = load_users()
    for u, info in users.items():
        if token in tokens_of(info):
            return u
    return None

# ---------- 模型 ----------
class AuthBody(BaseModel):
    username: str
    password: str
    defaults: dict | None = None

class DataBody(BaseModel):
    data: dict

# ---------- 接口 ----------
@app.get("/api/health")
def health():
    """前端/运维用来判断这个地址背后是不是真的记账本后端"""
    return {
        "ok": True,
        "service": "forest-accounting",
        "version": 2,
        "users": len(load_users()),
        "uptime": int(time.time() - BOOT_TIME),
    }

@app.post("/api/register")
def register(body: AuthBody):
    username = body.username.strip()
    password = body.password
    if len(username) < 2:
        return {"success": False, "message": "账号至少 2 个字符"}
    if len(password) < 4:
        return {"success": False, "message": "密码至少 4 位"}

    users = load_users()
    if username in users:
        return {"success": False, "message": "账号已存在"}

    salt = secrets.token_hex(8)
    book = new_book(normalize_defaults(body.defaults))
    users[username] = {
        "salt": salt,
        "pwd": hash_pwd(password, salt),
        "token": "",
        "tokens": [],
        "created_at": int(time.time()),
        "data": book,
    }
    token = issue_token(users[username])
    save_users(users)
    user_data_path(username).write_text(
        json.dumps(book, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"success": True, "token": token, "data": book}

@app.post("/api/login")
def login(body: AuthBody):
    username = body.username.strip()
    password = body.password

    users = load_users()
    user = users.get(username)
    if not user:
        return {"success": False, "message": "账号不存在，请先注册"}
    if user["pwd"] != hash_pwd(password, user["salt"]):
        return {"success": False, "message": "密码错误"}

    # 签发新 token，但保留其它设备已有的 token（不互相顶下线）
    issue_token(user)
    save_users(users)
    return {"success": True, "token": user["token"], "data": user.get("data", {})}

def _auth(request: Request, authorization: str | None = Header(default=None),
          x_auth_token: str | None = Header(default=None)):
    """从多个来源依次尝试 token。
    注意：云平台网关会注入自己的 Authorization 头，因此必须优先使用
    自定义头 X-Auth-Token / query 参数，Authorization 仅作兜底。"""
    candidates = []
    if x_auth_token:
        candidates.append(x_auth_token)
    if "token" in request.query_params:
        candidates.append(request.query_params["token"])
    if authorization and authorization.startswith("Bearer "):
        candidates.append(authorization[7:])

    for tok in candidates:
        username = get_username_from_token(tok)
        if username:
            return username
    raise HTTPException(status_code=401, detail="未登录")

@app.get("/api/data")
def get_data(request: Request, authorization: str | None = Header(default=None),
            x_auth_token: str | None = Header(default=None)):
    username = _auth(request, authorization, x_auth_token)
    path = user_data_path(username)
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    if not data:
        users = load_users()
        data = users.get(username, {}).get("data", {}) or {}
    return {"success": True, "data": data}

@app.put("/api/data")
def put_data(body: DataBody, request: Request,
             authorization: str | None = Header(default=None),
             x_auth_token: str | None = Header(default=None)):
    username = _auth(request, authorization, x_auth_token)
    path = user_data_path(username)
    path.write_text(json.dumps(body.data, ensure_ascii=False, indent=2), encoding="utf-8")
    # 同步到 users.json 备份
    users = load_users()
    if username in users:
        users[username]["data"] = body.data
        save_users(users)
    return {"success": True, "updated_at": int(time.time() * 1000)}

# ---------- 页面路由 ----------
# 说明：必须以重定向方式进入 /static/ 下的页面，否则相对路径
# （./accounting.html、./sw.js、./manifest.json）会解析到根路径而 404。
@app.get("/")
def index():
    # 兼容老部署：static/ 里没有 index.html 时回退到 login.html
    target = "/static/index.html" if (STATIC_DIR / "index.html").exists() else "/static/login.html"
    return RedirectResponse(url=target)

@app.get("/login.html")
def login_page():
    return FileResponse(STATIC_DIR / "login.html")

@app.get("/accounting.html")
def accounting_page():
    return FileResponse(STATIC_DIR / "accounting.html")

@app.get("/manifest.json")
def manifest_page():
    return FileResponse(STATIC_DIR / "manifest.json")

@app.get("/sw.js")
def sw_page():
    return FileResponse(STATIC_DIR / "sw.js")

@app.get("/favicon.ico")
def favicon():
    f = STATIC_DIR / "favicon.png"
    return FileResponse(f) if f.exists() else {"error": "no favicon"}

app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # 支持平台注入的 PORT 环境变量（云部署），本地默认 8000
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
