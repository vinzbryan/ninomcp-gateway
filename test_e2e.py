#!/usr/bin/env python3
"""End-to-end test for NinoMCP Gateway.

Prereqs: gateway on :8000 (fresh DB) and demo_upstream on :9001.
Run: .venv/bin/python test_e2e.py
"""
import base64
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import httpx

GW = "http://127.0.0.1:8000"
DEMO = "http://127.0.0.1:9001"
FAILURES = []

def check(name, cond, extra=""):
    print(("PASS" if cond else "FAIL"), "-", name, extra if not cond else "")
    if not cond:
        FAILURES.append(name)

def rpc(client, url, key, method, params=None, req_id=1):
    r = client.post(url, headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
                    json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
    return r

def main():
    # demo sqlite db for the SQL upstream
    dbfile = Path(__file__).parent / "data" / "demo.db"
    conn = sqlite3.connect(dbfile)
    conn.execute("DROP TABLE IF EXISTS items")
    conn.execute("CREATE TABLE items(id INTEGER, label TEXT)")
    conn.executemany("INSERT INTO items VALUES(?,?)", [(1, "alpha"), (2, "beta")])
    conn.commit(); conn.close()

    c = httpx.Client(timeout=30, follow_redirects=False, trust_env=False)
    check("health", c.get(GW + "/health").json().get("ok") is True)

    r = c.post(GW + "/admin/login", json={"username": "admin", "password": "changeme"})
    check("admin login", r.status_code == 200, r.text)
    admin = {"Authorization": "Bearer " + r.json()["token"]}

    r = c.post(GW + "/admin/keys", headers=admin, json={"name": "admin-key"})
    admin_key = r.json()["api_key"]
    check("create admin api key", admin_key.startswith("gw_"))

    r = c.post(GW + "/admin/users", headers=admin,
               json={"username": "budi", "password": "secret123", "role": "user"})
    uid = r.json()["id"]
    r = c.post(GW + "/admin/keys", headers=admin, json={"name": "budi-key", "user_id": uid})
    user_key = r.json()["api_key"]
    check("create user + key", bool(user_key))

    # OpenAPI import
    r = c.post(GW + "/admin/upstreams/openapi", headers=admin,
               json={"server_id": 1, "name": "Demo Shop", "spec_url": DEMO + "/openapi.json",
                     "base_url": DEMO})
    tools = r.json().get("tools_created", [])
    check("openapi import creates tools", "list_products" in tools and "get_product" in tools, r.text)

    # GraphQL upstream
    r = c.post(GW + "/admin/upstreams", headers=admin,
               json={"server_id": 1, "name": "Demo GraphQL", "type": "graphql",
                     "config": {"base_url": DEMO + "/graphql", "headers": {}}})
    check("graphql upstream", "demo_graphql_query" in r.json().get("tools_created", []), r.text)

    # SQL upstream
    r = c.post(GW + "/admin/upstreams", headers=admin,
               json={"server_id": 1, "name": "Demo DB", "type": "sql",
                     "config": {"db_path": str(dbfile)}})
    check("sql upstream", "demo_db_sql" in r.json().get("tools_created", []), r.text)

    # MCP protocol
    r = rpc(c, GW + "/mcp", admin_key, "initialize", {"protocolVersion": "2025-06-18"})
    check("mcp initialize", r.json()["result"]["serverInfo"]["name"] == "ninomcp-gateway", r.text)
    r = rpc(c, GW + "/mcp/default", admin_key, "tools/list")
    names = [t["name"] for t in r.json()["result"]["tools"]]
    check("tools/list", all(x in names for x in ("list_products", "demo_graphql_query", "demo_db_sql")), str(names))

    r = rpc(c, GW + "/mcp/default", admin_key, "tools/call", {"name": "list_products", "arguments": {}})
    check("call list_products", "Keyboard" in json.dumps(r.json()), r.text)

    r = rpc(c, GW + "/mcp/default", admin_key, "tools/call",
            {"name": "get_product", "arguments": {"product_id": 2}})
    check("call get_product (path param)", "Mouse" in json.dumps(r.json()), r.text)

    r = rpc(c, GW + "/mcp/default", admin_key, "tools/call",
            {"name": "demo_db_sql", "arguments": {"query": "SELECT * FROM items ORDER BY id"}})
    check("call sql select", "alpha" in json.dumps(r.json()), r.text)

    r = rpc(c, GW + "/mcp/default", admin_key, "tools/call",
            {"name": "demo_db_sql", "arguments": {"query": "DELETE FROM items"}})
    check("sql write blocked", r.json()["result"].get("isError") is True, r.text)

    r = rpc(c, GW + "/mcp/default", admin_key, "tools/call",
            {"name": "demo_graphql_query", "arguments": {"query": "{ products { name } }"}})
    check("call graphql", "Keyboard" in json.dumps(r.json()), r.text)

    # auth + RBAC
    r = c.post(GW + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    check("unauthenticated rejected", r.status_code == 401, str(r.status_code))
    tid = [t for t in c.get(GW + "/admin/tools", headers=admin).json() if t["name"] == "list_products"][0]["id"]
    c.patch(GW + f"/admin/tools/{tid}", headers=admin, json={"allowed_roles": ["admin"]})
    r = rpc(c, GW + "/mcp/default", user_key, "tools/list")
    names_user = [t["name"] for t in r.json()["result"]["tools"]]
    check("rbac hides admin-only tool", "list_products" not in names_user and "demo_db_sql" in names_user, str(names_user))
    r = rpc(c, GW + "/mcp/default", user_key, "tools/call", {"name": "list_products", "arguments": {}})
    check("rbac blocks call", "error" in r.json(), r.text)

    # MCP bridge: new server importing this gateway's own /mcp/default tools
    r = c.post(GW + "/admin/servers", headers=admin, json={"slug": "bridge", "name": "Bridge"})
    bridge_id = r.json()["id"]
    r = c.post(GW + "/admin/upstreams", headers=admin,
               json={"server_id": bridge_id, "name": "Self Bridge", "type": "mcp",
                     "config": {"base_url": GW + "/mcp/default",
                                "headers": {"Authorization": f"Bearer {admin_key}"}}})
    check("mcp bridge import", "get_product" in r.json().get("tools_created", []), r.text)
    r = rpc(c, GW + "/mcp/bridge", admin_key, "tools/call",
            {"name": "get_product", "arguments": {"product_id": 3}})
    check("mcp bridge call proxied", "Monitor" in json.dumps(r.json()), r.text)

    # OAuth 2.0 flow with PKCE
    r = c.post(GW + "/register", json={"client_name": "test", "redirect_uris": ["http://127.0.0.1:9999/cb"],
                                       "token_endpoint_auth_method": "none"})
    client_id = r.json()["client_id"]
    verifier = "test-verifier-1234567890"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = c.post(GW + "/authorize", data={"username": "admin", "password": "changeme",
                                        "client_id": client_id, "redirect_uri": "http://127.0.0.1:9999/cb",
                                        "state": "xyz", "code_challenge": challenge})
    check("oauth authorize redirects with code", r.status_code == 302 and "code=" in r.headers.get("location", ""), r.text)
    code = r.headers["location"].split("code=")[1].split("&")[0]
    r = c.post(GW + "/token", data={"grant_type": "authorization_code", "code": code,
                                    "client_id": client_id, "code_verifier": verifier})
    access = r.json().get("access_token")
    check("oauth token issued", bool(access), r.text)
    r = rpc(c, GW + "/mcp/default", access, "tools/list")
    check("oauth token works on /mcp", r.status_code == 200 and "result" in r.json(), r.text)

    # well-known metadata
    md = c.get(GW + "/.well-known/oauth-protected-resource").json()
    check("protected resource metadata", md["resource"].endswith("/mcp"), str(md))

    # audit log
    rows = c.get(GW + "/admin/audit", headers=admin).json()
    ok_calls = [x for x in rows if x["tool_name"] == "list_products" and x["status"] == "ok"]
    check("audit log records calls", len(ok_calls) >= 1, f"{len(rows)} rows")

    print()
    if FAILURES:
        print("FAILED:", FAILURES)
        sys.exit(1)
    print("ALL TESTS PASSED")

if __name__ == "__main__":
    main()
