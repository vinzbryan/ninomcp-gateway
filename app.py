#!/usr/bin/env python3
"""
NinoMCP Gateway — a self-hosted MCP gateway in the spirit of AnythingMCP.

Turns REST/OpenAPI, GraphQL, SQL (SQLite) upstreams and other MCP servers
into MCP tools behind one authenticated, role-gated, audit-logged endpoint.

Protocol: MCP Streamable HTTP (stateless), JSON-RPC 2.0.
Endpoints:
  POST /mcp                -> all servers' tools
  POST /mcp/{server_slug}  -> one server's tools
  OAuth 2.0: /authorize /token /register /revoke + /.well-known/*
  Admin API: /admin/*      Dashboard: /
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("GATEWAY_DATA_DIR", BASE_DIR / "data"))
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass  # read-only filesystem (e.g. serverless): GATEWAY_DATA_DIR should point to /tmp
DB_PATH = Path(os.environ.get("GATEWAY_DB", DATA_DIR / "gateway.db"))
PUBLIC_BASE_ENV = os.environ.get("GATEWAY_PUBLIC_BASE", "").rstrip("/")
PUBLIC_BASE = PUBLIC_BASE_ENV or "http://localhost:8000"


def public_base(request: Optional[Request] = None) -> str:
    """Public base URL for OAuth metadata. Explicit env wins; otherwise derive
    it from the (forwarded) request host so proxied/serverless deployments
    (e.g. Vercel) advertise their real public URL instead of localhost."""
    if PUBLIC_BASE_ENV:
        return PUBLIC_BASE_ENV
    if request is not None:
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc).split(",")[0].strip()
        if host:
            return f"{proto}://{host}".rstrip("/")
    return PUBLIC_BASE

# ---------------------------------------------------------------- secrets ---
def _load_secret() -> bytes:
    env = os.environ.get("GATEWAY_SECRET")
    if env:
        return env.encode()
    f = DATA_DIR / "secret.key"
    try:
        if not f.exists():
            f.write_bytes(secrets.token_bytes(32))
        return f.read_bytes()
    except OSError:
        return secrets.token_bytes(32)  # ephemeral fallback on read-only filesystems

SECRET = _load_secret()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 120_000)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()

def check_password(pw: str, stored: str) -> bool:
    try:
        salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt_b64), 120_000)
        return hmac.compare_digest(base64.b64encode(dk).decode(), dk_b64)
    except Exception:
        return False

def sign_token(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
    return raw + "." + sig

def verify_token(token: str) -> Optional[dict]:
    try:
        raw, sig = token.rsplit(".", 1)
        expect = hmac.new(SECRET, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return None
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# --------------------------------------------------------------------- db ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT,
  key_hash TEXT UNIQUE NOT NULL, key_prefix TEXT, created_at REAL, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS servers(
  id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, description TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS upstreams(
  id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, name TEXT NOT NULL,
  type TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS tools(
  id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, upstream_id INTEGER,
  name TEXT NOT NULL, description TEXT DEFAULT '', input_schema TEXT NOT NULL DEFAULT '{}',
  kind TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}',
  allowed_roles TEXT NOT NULL DEFAULT '["admin","user"]', enabled INTEGER DEFAULT 1,
  UNIQUE(server_id, name));
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY, ts REAL, actor TEXT, server_slug TEXT, tool_name TEXT,
  arguments TEXT, status TEXT, duration_ms INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS oauth_clients(
  client_id TEXT PRIMARY KEY, client_secret_hash TEXT, name TEXT,
  redirect_uris TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS oauth_codes(
  code TEXT PRIMARY KEY, client_id TEXT, user_id INTEGER, redirect_uri TEXT,
  code_challenge TEXT, expires REAL, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS oauth_tokens(
  token_hash TEXT PRIMARY KEY, kind TEXT, user_id INTEGER, client_id TEXT, expires REAL);
"""

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT COUNT(*) c FROM users").fetchone()
        if row["c"] == 0:
            admin_pw = os.environ.get("GATEWAY_ADMIN_PASSWORD", "changeme")
            conn.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')",
                (os.environ.get("GATEWAY_ADMIN_USER", "admin"), hash_password(admin_pw)))
            conn.execute(
                "INSERT INTO servers(slug,name,description) VALUES('default','Default','Default MCP server')")

def audit(actor: str, server_slug: str, tool: str, args: dict, status: str,
          duration_ms: int, error: str = ""):
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_log(ts,actor,server_slug,tool_name,arguments,status,duration_ms,error)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), actor, server_slug, tool,
             json.dumps(args)[:2000], status, duration_ms, error[:500]))

# ------------------------------------------------------------------- auth ---
def resolve_actor(request: Request) -> Optional[dict]:
    """Return {user_id, username, role, via} from Bearer API key / OAuth token / session."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    # session token (dashboard)
    payload = verify_token(token)
    if payload and payload.get("typ") == "session":
        with db() as conn:
            u = conn.execute("SELECT * FROM users WHERE id=?", (payload["uid"],)).fetchone()
        if u:
            return {"user_id": u["id"], "username": u["username"], "role": u["role"], "via": "session"}
    th = sha256_hex(token)
    with db() as conn:
        k = conn.execute(
            "SELECT u.* FROM api_keys k JOIN users u ON u.id=k.user_id"
            " WHERE k.key_hash=? AND k.revoked=0", (th,)).fetchone()
        if k:
            return {"user_id": k["id"], "username": k["username"], "role": k["role"], "via": "api_key"}
        t = conn.execute("SELECT * FROM oauth_tokens WHERE token_hash=? AND expires>?",
                         (th, time.time())).fetchone()
        if t:
            u = conn.execute("SELECT * FROM users WHERE id=?", (t["user_id"],)).fetchone()
            if u:
                return {"user_id": u["id"], "username": u["username"], "role": u["role"], "via": "oauth"}
    return None

def require_actor(request: Request, admin: bool = False) -> Optional[dict]:
    actor = resolve_actor(request)
    if not actor:
        return None
    if admin and actor["role"] != "admin":
        return None
    return actor

app = FastAPI(title="NinoMCP Gateway", version="1.0.0")
init_db()

# ------------------------------------------------------------- executors ---
def _result_text(obj: Any) -> dict:
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": text}]}

async def exec_rest(tool: dict, args: dict) -> dict:
    cfg = tool["config"]
    upstream = tool["upstream"]
    path = cfg["path"]
    remaining = dict(args)
    for ph in re.findall(r"\{(\w+)\}", path):
        if ph in remaining:
            path = path.replace("{" + ph + "}", str(remaining.pop(ph)))
    headers = dict(upstream.get("headers", {}))
    url = upstream["base_url"].rstrip("/") + path
    method = cfg["method"].upper()
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        if method in ("GET", "DELETE"):
            r = await client.request(method, url, params=remaining, headers=headers)
        else:
            r = await client.request(method, url, json=remaining or None, headers=headers)
    try:
        body = r.json()
    except Exception:
        body = r.text
    return _result_text({"status_code": r.status_code, "body": body})

async def exec_graphql(tool: dict, args: dict) -> dict:
    upstream = tool["upstream"]
    headers = dict(upstream.get("headers", {}))
    payload = {"query": args.get("query", ""), "variables": args.get("variables", {})}
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        r = await client.post(upstream["base_url"], json=payload, headers=headers)
    try:
        return _result_text(r.json())
    except Exception:
        return _result_text(r.text)

BANNED_SQL = re.compile(r"\b(insert|update|delete|drop|alter|create|replace|truncate|attach|detach|pragma|vacuum)\b", re.I)

def exec_sql(tool: dict, args: dict) -> dict:
    upstream = tool["upstream"]
    query = (args.get("query") or tool["config"].get("query") or "").strip()
    if not query:
        raise ValueError("No SQL query provided")
    if ";" in query.rstrip(";") or not re.match(r"(?is)^\s*(select|with)\b", query) or BANNED_SQL.search(query):
        raise ValueError("Only a single read-only SELECT statement is allowed")
    conn = sqlite3.connect(f"file:{upstream['db_path']}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(query).fetchmany(500)]
    finally:
        conn.close()
    return _result_text({"rows": rows, "row_count": len(rows)})

async def _mcp_rpc(url: str, headers: dict, method: str, params: dict, req_id: int = 1) -> dict:
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        r = await client.post(url, json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
                              headers={"Accept": "application/json, text/event-stream", **headers})
    ctype = r.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        for line in r.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:])
        raise ValueError("Empty SSE response from upstream MCP server")
    return r.json()

async def exec_mcp_bridge(tool: dict, args: dict) -> dict:
    upstream = tool["upstream"]
    headers = dict(upstream.get("headers", {}))
    resp = await _mcp_rpc(upstream["base_url"], headers, "tools/call",
                          {"name": tool["config"]["remote_tool_name"], "arguments": args})
    if "error" in resp:
        raise ValueError(json.dumps(resp["error"]))
    return resp.get("result", _result_text(resp))

async def execute_tool(tool: dict, args: dict) -> dict:
    kind = tool["kind"]
    if kind in ("rest", "openapi"):
        return await exec_rest(tool, args)
    if kind == "graphql":
        return await exec_graphql(tool, args)
    if kind == "sql":
        return exec_sql(tool, args)
    if kind == "mcp":
        return await exec_mcp_bridge(tool, args)
    raise ValueError(f"Unknown tool kind: {kind}")

# ------------------------------------------------------------ MCP server ---
SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"]

def get_tools(server_slug: Optional[str], role: str) -> list:
    with db() as conn:
        if server_slug:
            s = conn.execute("SELECT * FROM servers WHERE slug=?", (server_slug,)).fetchone()
            if not s:
                return []
            rows = conn.execute("SELECT * FROM tools WHERE server_id=? AND enabled=1", (s["id"],)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM tools WHERE enabled=1").fetchall()
        out = []
        for t in rows:
            if role not in json.loads(t["allowed_roles"]):
                continue
            up = None
            if t["upstream_id"]:
                u = conn.execute("SELECT * FROM upstreams WHERE id=?", (t["upstream_id"],)).fetchone()
                if u:
                    up = json.loads(u["config"])
            out.append({"id": t["id"], "name": t["name"], "description": t["description"],
                        "input_schema": json.loads(t["input_schema"]), "kind": t["kind"],
                        "config": json.loads(t["config"]), "upstream": up or {},
                        "server_id": t["server_id"]})
        return out

async def handle_mcp(request: Request, server_slug: Optional[str]):
    actor = resolve_actor(request)
    if not actor:
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32001, "message": "Unauthorized: Bearer API key or OAuth token required"}},
                            status_code=401,
                            headers={"WWW-Authenticate": f'Bearer resource_metadata="{public_base(request)}/.well-known/oauth-protected-resource"'})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "Parse error"}}, status_code=400)
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params") or {}
    if req_id is None:  # notification
        return Response(status_code=202)
    def ok(result):
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})
    def err(code, msg):
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}})
    if method == "initialize":
        pv = params.get("protocolVersion", SUPPORTED_PROTOCOLS[0])
        if pv not in SUPPORTED_PROTOCOLS:
            pv = SUPPORTED_PROTOCOLS[0]
        return ok({"protocolVersion": pv, "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "ninomcp-gateway", "version": "1.0.0"}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        tools = get_tools(server_slug, actor["role"])
        return ok({"tools": [{"name": t["name"], "description": t["description"],
                              "inputSchema": t["input_schema"]} for t in tools]})
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        tools = {t["name"]: t for t in get_tools(server_slug, actor["role"])}
        if name not in tools:
            return err(-32602, f"Tool not found or not permitted for role {actor['role']}: {name}")
        started = time.time()
        try:
            result = await execute_tool(tools[name], args)
            audit(actor["username"], server_slug or "all", name, args, "ok",
                  int((time.time() - started) * 1000))
            if result.get("isError"):
                pass
            return ok(result)
        except Exception as e:
            audit(actor["username"], server_slug or "all", name, args, "error",
                  int((time.time() - started) * 1000), str(e))
            return ok({"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True})
    return err(-32601, f"Method not found: {method}")

@app.post("/mcp")
async def mcp_all(request: Request):
    return await handle_mcp(request, None)

@app.post("/mcp/{server_slug}")
async def mcp_one(request: Request, server_slug: str):
    return await handle_mcp(request, server_slug)

@app.get("/mcp")
async def mcp_get():
    return JSONResponse({"error": "Stateless server: use POST"}, status_code=405)

# ------------------------------------------------------------------ OAuth --
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource(request: Request):
    base = public_base(request)
    return {"resource": base + "/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"]}

@app.get("/.well-known/oauth-protected-resource/{resource_path:path}")
async def protected_resource_path(request: Request, resource_path: str):
    # RFC 9728 path-appended variant, e.g. /.well-known/oauth-protected-resource/mcp
    base = public_base(request)
    return {"resource": base + "/" + resource_path,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"]}

@app.get("/.well-known/oauth-authorization-server")
async def as_metadata(request: Request):
    base = public_base(request)
    return {"issuer": base,
            "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token",
            "registration_endpoint": base + "/register",
            "revocation_endpoint": base + "/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "email"]}

@app.get("/.well-known/openid-configuration")
async def oidc_configuration(request: Request):
    # Same discovery document as the OAuth AS metadata; some clients probe
    # the OIDC path first when the "openid" scope is requested.
    return await as_metadata(request)

@app.post("/register")
async def register_client(request: Request):
    body = await request.json()
    client_id = "gw_" + secrets.token_urlsafe(12)
    secret = secrets.token_urlsafe(24)
    auth_method = body.get("token_endpoint_auth_method", "none")
    with db() as conn:
        conn.execute("INSERT INTO oauth_clients(client_id,client_secret_hash,name,redirect_uris) VALUES(?,?,?,?)",
                     (client_id, None if auth_method == "none" else sha256_hex(secret),
                      body.get("client_name", ""), json.dumps(body.get("redirect_uris", []))))
    out = {"client_id": client_id, "token_endpoint_auth_method": auth_method,
           "redirect_uris": body.get("redirect_uris", [])}
    if auth_method != "none":
        out["client_secret"] = secret
    return out

LOGIN_FORM = """<!doctype html><title>Sign in — NinoMCP Gateway</title>
<body style="font-family:sans-serif;max-width:360px;margin:60px auto">
<h2>Sign in to authorize</h2><form method="post">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<p><input name="username" placeholder="Username" required style="width:100%;padding:8px"></p>
<p><input name="password" type="password" placeholder="Password" required style="width:100%;padding:8px"></p>
<p style="color:#b00">{error}</p>
<button style="padding:8px 16px">Sign in &amp; authorize</button></form></body>"""

@app.get("/authorize")
async def authorize_form(request: Request):
    q = request.query_params
    return HTMLResponse(LOGIN_FORM.format(client_id=q.get("client_id", ""), redirect_uri=q.get("redirect_uri", ""),
                                          state=q.get("state", ""), code_challenge=q.get("code_challenge", ""), error=""))

@app.post("/authorize")
async def authorize_submit(request: Request):
    form = await request.form()
    username, password = form.get("username", ""), form.get("password", "")
    client_id, redirect_uri = form.get("client_id", ""), form.get("redirect_uri", "")
    state, challenge = form.get("state", ""), form.get("code_challenge", "")
    with db() as conn:
        u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        c = conn.execute("SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
    if not u or not check_password(password, u["password_hash"]) or not c:
        return HTMLResponse(LOGIN_FORM.format(client_id=client_id, redirect_uri=redirect_uri, state=state,
                                              code_challenge=challenge, error="Invalid credentials or client"), status_code=401)
    if redirect_uri not in json.loads(c["redirect_uris"]):
        return HTMLResponse("redirect_uri not registered for this client", status_code=400)
    code = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO oauth_codes(code,client_id,user_id,redirect_uri,code_challenge,expires) VALUES(?,?,?,?,?,?)",
                     (code, client_id, u["id"], redirect_uri, challenge, time.time() + 600))
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=302)

@app.post("/token")
async def token_endpoint(request: Request):
    form = await request.form()
    grant = form.get("grant_type", "")
    with db() as conn:
        if grant == "authorization_code":
            row = conn.execute("SELECT * FROM oauth_codes WHERE code=? AND used=0 AND expires>?",
                               (form.get("code", ""), time.time())).fetchone()
            if not row:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if row["code_challenge"]:
                verifier = form.get("code_verifier", "")
                digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
                if not hmac.compare_digest(digest, row["code_challenge"]):
                    return JSONResponse({"error": "invalid_grant", "error_description": "PKCE check failed"}, status_code=400)
            conn.execute("UPDATE oauth_codes SET used=1 WHERE code=?", (form.get("code", ""),))
            user_id, client_id = row["user_id"], row["client_id"]
        elif grant == "refresh_token":
            rt = conn.execute("SELECT * FROM oauth_tokens WHERE token_hash=? AND kind='refresh' AND expires>?",
                              (sha256_hex(form.get("refresh_token", "")), time.time())).fetchone()
            if not rt:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            conn.execute("DELETE FROM oauth_tokens WHERE token_hash=?", (rt["token_hash"],))
            user_id, client_id = rt["user_id"], rt["client_id"]
        else:
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO oauth_tokens VALUES(?,?,?,?,?)",
                     (sha256_hex(access), "access", user_id, client_id, time.time() + 3600))
        conn.execute("INSERT INTO oauth_tokens VALUES(?,?,?,?,?)",
                     (sha256_hex(refresh), "refresh", user_id, client_id, time.time() + 30 * 86400))
    return {"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh}

@app.post("/revoke")
async def revoke_endpoint(request: Request):
    form = await request.form()
    with db() as conn:
        conn.execute("DELETE FROM oauth_tokens WHERE token_hash=?", (sha256_hex(form.get("token", "")),))
    return {}

# ------------------------------------------------------------- OpenAPI -----
def sanitize_tool_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name).lower()[:60] or "tool"

def import_openapi(server_id: int, name: str, spec: dict, base_url_override: str = "") -> dict:
    base_url = base_url_override
    if not base_url and spec.get("servers"):
        base_url = spec["servers"][0].get("url", "")
    with db() as conn:
        cur = conn.execute("INSERT INTO upstreams(server_id,name,type,config) VALUES(?,?,'openapi',?)",
                           (server_id, name, json.dumps({"base_url": base_url, "headers": {}})))
        upstream_id = cur.lastrowid
        created = []
        for path, methods in (spec.get("paths") or {}).items():
            for method, op in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                tname = sanitize_tool_name(op.get("operationId") or f"{method}_{path.strip('/').replace('/', '_')}")
                props, required = {}, []
                for p in op.get("parameters", []):
                    props[p["name"]] = p.get("schema", {"type": "string"})
                    if p.get("required"):
                        required.append(p["name"])
                body_schema = ((op.get("requestBody") or {}).get("content", {})
                               .get("application/json", {}).get("schema", {}))
                for pname, pschema in (body_schema.get("properties") or {}).items():
                    props[pname] = pschema
                required += body_schema.get("required", [])
                schema = {"type": "object", "properties": props, "required": sorted(set(required))}
                try:
                    conn.execute(
                        "INSERT INTO tools(server_id,upstream_id,name,description,input_schema,kind,config)"
                        " VALUES(?,?,?,?,?,'openapi',?)",
                        (server_id, upstream_id, tname, (op.get("summary") or "")[:500],
                         json.dumps(schema), json.dumps({"method": method.upper(), "path": path})))
                    created.append(tname)
                except sqlite3.IntegrityError:
                    pass
    return {"upstream_id": upstream_id, "tools_created": created}

# -------------------------------------------------------------- admin API --
def admin_guard(request: Request):
    actor = require_actor(request, admin=True)
    if not actor:
        return None, JSONResponse({"error": "Admin authentication required"}, status_code=401)
    return actor, None

@app.post("/admin/login")
async def admin_login(request: Request):
    body = await request.json()
    with db() as conn:
        u = conn.execute("SELECT * FROM users WHERE username=?", (body.get("username", ""),)).fetchone()
    if not u or not check_password(body.get("password", ""), u["password_hash"]):
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    token = sign_token({"typ": "session", "uid": u["id"], "exp": time.time() + 12 * 3600})
    return {"token": token, "username": u["username"], "role": u["role"]}

@app.get("/admin/servers")
async def list_servers(request: Request):
    _, e = admin_guard(request)
    if e: return e
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM servers ORDER BY id")]

@app.post("/admin/servers")
async def create_server(request: Request):
    _, e = admin_guard(request)
    if e: return e
    body = await request.json()
    with db() as conn:
        cur = conn.execute("INSERT INTO servers(slug,name,description) VALUES(?,?,?)",
                           (body["slug"], body["name"], body.get("description", "")))
        return {"id": cur.lastrowid, "slug": body["slug"]}

@app.get("/admin/upstreams")
async def list_upstreams(request: Request):
    _, e = admin_guard(request)
    if e: return e
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM upstreams ORDER BY id")]

@app.post("/admin/upstreams")
async def create_upstream(request: Request):
    """Create a rest / graphql / sql / mcp upstream, plus its starter tool(s)."""
    _, e = admin_guard(request)
    if e: return e
    body = await request.json()
    typ, cfg = body["type"], body.get("config", {})
    with db() as conn:
        cur = conn.execute("INSERT INTO upstreams(server_id,name,type,config) VALUES(?,?,?,?)",
                           (body["server_id"], body["name"], typ, json.dumps(cfg)))
        upstream_id = cur.lastrowid
    tools_made = []
    if typ == "graphql":
        with db() as conn:
            conn.execute("INSERT INTO tools(server_id,upstream_id,name,description,input_schema,kind,config)"
                         " VALUES(?,?,?,?,?,'graphql','{}')",
                         (body["server_id"], upstream_id, body.get("tool_name", sanitize_tool_name(body["name"]) + "_query"),
                          "Run a GraphQL query against " + body["name"],
                          json.dumps({"type": "object", "properties": {
                              "query": {"type": "string"}, "variables": {"type": "object"}}, "required": ["query"]})))
        tools_made.append(body.get("tool_name", sanitize_tool_name(body["name"]) + "_query"))
    elif typ == "sql":
        with db() as conn:
            conn.execute("INSERT INTO tools(server_id,upstream_id,name,description,input_schema,kind,config)"
                         " VALUES(?,?,?,?,?,'sql','{}')",
                         (body["server_id"], upstream_id, body.get("tool_name", sanitize_tool_name(body["name"]) + "_sql"),
                          "Run a read-only SELECT query against " + body["name"],
                          json.dumps({"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]})))
        tools_made.append(body.get("tool_name", sanitize_tool_name(body["name"]) + "_sql"))
    elif typ == "mcp":
        resp = await _mcp_rpc(cfg["base_url"], cfg.get("headers", {}), "initialize",
                              {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "ninomcp-gateway", "version": "1.0.0"}})
        listed = await _mcp_rpc(cfg["base_url"], cfg.get("headers", {}), "tools/list", {}, req_id=2)
        remote_tools = (listed.get("result") or {}).get("tools", [])
        with db() as conn:
            for t in remote_tools:
                try:
                    conn.execute("INSERT INTO tools(server_id,upstream_id,name,description,input_schema,kind,config)"
                                 " VALUES(?,?,?,?,?,'mcp',?)",
                                 (body["server_id"], upstream_id, t["name"], t.get("description", ""),
                                  json.dumps(t.get("inputSchema", {"type": "object"})),
                                  json.dumps({"remote_tool_name": t["name"]})))
                    tools_made.append(t["name"])
                except sqlite3.IntegrityError:
                    pass
    return {"upstream_id": upstream_id, "tools_created": tools_made}

@app.post("/admin/upstreams/openapi")
async def create_openapi_upstream(request: Request):
    _, e = admin_guard(request)
    if e: return e
    body = await request.json()
    spec = body.get("spec")
    if not spec and body.get("spec_url"):
        async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
            r = await client.get(body["spec_url"])
        text = r.text
        try:
            spec = json.loads(text)
        except Exception:
            spec = yaml.safe_load(text)
    if not spec:
        return JSONResponse({"error": "Provide spec (JSON object) or spec_url"}, status_code=400)
    return import_openapi(body["server_id"], body["name"], spec, body.get("base_url", ""))

@app.post("/admin/tools")
async def create_tool(request: Request):
    """Create a single REST tool manually."""
    _, e = admin_guard(request)
    if e: return e
    body = await request.json()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO tools(server_id,upstream_id,name,description,input_schema,kind,config,allowed_roles)"
            " VALUES(?,?,?,?,?,'rest',?,?)",
            (body["server_id"], body.get("upstream_id"), body["name"], body.get("description", ""),
             json.dumps(body.get("input_schema", {"type": "object", "properties": {}})),
             json.dumps({"method": body.get("method", "GET"), "path": body["path"]}),
             json.dumps(body.get("allowed_roles", ["admin", "user"]))))
        return {"id": cur.lastrowid}

@app.get("/admin/tools")
async def list_tools(request: Request):
    _, e = admin_guard(request)
    if e: return e
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM tools ORDER BY id")]

@app.patch("/admin/tools/{tool_id}")
async def update_tool(request: Request, tool_id: int):
    _, e = admin_guard(request)
    if e: return e
    body = await request.json()
    fields = {k: v for k, v in body.items() if k in ("enabled", "description")}
    if "allowed_roles" in body:
        fields["allowed_roles"] = json.dumps(body["allowed_roles"])
    if not fields:
        return JSONResponse({"error": "Nothing to update"}, status_code=400)
    with db() as conn:
        conn.execute("UPDATE tools SET " + ",".join(f"{k}=?" for k in fields) + " WHERE id=?",
                     (*fields.values(), tool_id))
    return {"ok": True}

@app.get("/admin/users")
async def list_users(request: Request):
    _, e = admin_guard(request)
    if e: return e
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT id,username,role FROM users ORDER BY id")]

@app.post("/admin/users")
async def create_user(request: Request):
    _, e = admin_guard(request)
    if e: return e
    body = await request.json()
    with db() as conn:
        cur = conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                           (body["username"], hash_password(body["password"]), body.get("role", "user")))
        return {"id": cur.lastrowid}

@app.post("/admin/keys")
async def create_key(request: Request):
    actor, e = admin_guard(request)
    if e: return e
    body = await request.json()
    user_id = body.get("user_id", actor["user_id"])
    key = "gw_" + secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO api_keys(user_id,name,key_hash,key_prefix,created_at) VALUES(?,?,?,?,?)",
                     (user_id, body.get("name", ""), sha256_hex(key), key[:10], time.time()))
    return {"api_key": key, "note": "Shown once — store it securely."}

@app.get("/admin/keys")
async def list_keys(request: Request):
    _, e = admin_guard(request)
    if e: return e
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id,user_id,name,key_prefix,created_at,revoked FROM api_keys ORDER BY id")]

@app.get("/admin/audit")
async def list_audit(request: Request):
    _, e = admin_guard(request)
    if e: return e
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")]

@app.get("/health")
async def health():
    return {"ok": True, "service": "ninomcp-gateway"}

# -------------------------------------------------------------- dashboard --
DASHBOARD = r"""<!doctype html>
<title>NinoMCP Gateway — Dashboard</title>
<meta charset="utf-8">
<style>
body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#222}
h1{font-size:20px} h2{font-size:16px;margin-top:28px}
table{border-collapse:collapse;width:100%;font-size:13px}
td,th{border:1px solid #ddd;padding:5px 7px;text-align:left;vertical-align:top}
input,select,textarea{padding:6px;margin:2px 0;width:100%;box-sizing:border-box}
button{padding:6px 12px;cursor:pointer}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
pre{background:#f6f6f6;padding:8px;overflow:auto;font-size:12px;max-height:300px}
.mut{color:#777;font-size:12px}
</style>
<h1>NinoMCP Gateway</h1>
<div id="login">
  <p class="mut">Sign in with an admin account (default: admin / changeme — change it).</p>
  <input id="u" placeholder="Username"><input id="p" type="password" placeholder="Password">
  <button onclick="login()">Sign in</button>
</div>
<div id="main" style="display:none">
  <p class="mut">MCP endpoints: <code>POST /mcp</code> (all servers) · <code>POST /mcp/&lt;slug&gt;</code> (one server).
  Auth: Bearer API key or OAuth 2.0 access token.</p>
  <div class="row">
    <div>
      <h2>MCP Servers</h2><div id="servers"></div>
      <input id="s_slug" placeholder="slug"><input id="s_name" placeholder="name">
      <button onclick="addServer()">Add server</button>
      <h2>Upstreams</h2><div id="upstreams"></div>
      <input id="up_name" placeholder="name">
      <select id="up_type"><option>rest</option><option>graphql</option><option>sql</option><option>mcp</option></select>
      <input id="up_server" placeholder="server_id (number)">
      <textarea id="up_config" rows="3" placeholder='config JSON — rest/graphql/mcp: {"base_url":"https://…","headers":{}} · sql: {"db_path":"/path/file.db"}'></textarea>
      <button onclick="addUpstream()">Add upstream</button>
      <h2>Import OpenAPI</h2>
      <input id="oa_name" placeholder="name"><input id="oa_server" placeholder="server_id (number)">
      <input id="oa_url" placeholder="spec_url (https://…/openapi.json)">
      <input id="oa_base" placeholder="base_url override (optional)">
      <button onclick="importOpenapi()">Import</button>
    </div>
    <div>
      <h2>API Keys</h2><div id="keys"></div>
      <input id="k_name" placeholder="key name"><button onclick="addKey()">Create key</button>
      <pre id="newkey"></pre>
      <h2>Users</h2><div id="users"></div>
      <input id="us_name" placeholder="username"><input id="us_pw" placeholder="password">
      <select id="us_role"><option>user</option><option>admin</option></select>
      <button onclick="addUser()">Add user</button>
      <h2>Tools</h2><div id="tools"></div>
    </div>
  </div>
  <h2>Audit Log (latest)</h2><div id="audit"></div>
</div>
<script>
let T = localStorage.getItem('gw_token') || '';
async function api(path, opts={}) {
  const r = await fetch(path, {headers: {'Authorization': 'Bearer ' + T, 'Content-Type': 'application/json'}, ...opts});
  if (!r.ok) throw new Error(path + ' -> ' + r.status);
  return r.json();
}
function tbl(rows, cols) {
  if (!rows.length) return '<p class="mut">empty</p>';
  return '<table><tr>' + cols.map(c => '<th>' + c + '</th>').join('') + '</tr>' +
    rows.map(r => '<tr>' + cols.map(c => '<td>' + String(r[c] ?? '').slice(0, 120) + '</td>').join('') + '</tr>').join('') + '</table>';
}
async function refresh() {
  document.getElementById('servers').innerHTML = tbl(await api('/admin/servers'), ['id','slug','name']);
  document.getElementById('upstreams').innerHTML = tbl(await api('/admin/upstreams'), ['id','server_id','name','type']);
  document.getElementById('tools').innerHTML = tbl(await api('/admin/tools'), ['id','name','kind','allowed_roles','enabled']);
  document.getElementById('keys').innerHTML = tbl(await api('/admin/keys'), ['id','name','key_prefix','revoked']);
  document.getElementById('users').innerHTML = tbl(await api('/admin/users'), ['id','username','role']);
  const a = await api('/admin/audit');
  document.getElementById('audit').innerHTML = tbl(a.map(x => ({...x, when: new Date(x.ts*1000).toLocaleString()})),
    ['id','when','actor','server_slug','tool_name','status','duration_ms']);
}
async function login() {
  const r = await fetch('/admin/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: u.value, password: p.value})});
  if (!r.ok) return alert('Login failed');
  T = (await r.json()).token; localStorage.setItem('gw_token', T); show();
}
function show() { login.style.display = 'none'; main.style.display = 'block'; refresh(); }
async function addServer() { await api('/admin/servers', {method: 'POST', body: JSON.stringify({slug: s_slug.value, name: s_name.value})}); refresh(); }
async function addUpstream() { await api('/admin/upstreams', {method: 'POST', body: JSON.stringify({name: up_name.value, type: up_type.value, server_id: +up_server.value, config: JSON.parse(up_config.value || '{}')})}); refresh(); }
async function importOpenapi() { const j = await api('/admin/upstreams/openapi', {method: 'POST', body: JSON.stringify({name: oa_name.value, server_id: +oa_server.value, spec_url: oa_url.value, base_url: oa_base.value})}); alert('Tools: ' + j.tools_created.join(', ')); refresh(); }
async function addKey() { const j = await api('/admin/keys', {method: 'POST', body: JSON.stringify({name: k_name.value})}); newkey.textContent = j.api_key; refresh(); }
async function addUser() { await api('/admin/users', {method: 'POST', body: JSON.stringify({username: us_name.value, password: us_pw.value, role: us_role.value})}); refresh(); }
if (T) show();
</script>
"""

@app.get("/")
async def dashboard():
    return HTMLResponse(DASHBOARD)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("GATEWAY_HOST", "0.0.0.0"),
                port=int(os.environ.get("GATEWAY_PORT", "8000")))
