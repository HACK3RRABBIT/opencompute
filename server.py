#!/usr/bin/env python3
"""
OpenCompute — Load Balancer for discovered Ollama-compatible model endpoints.
- Passive discovery (crt.sh, HackerTarget, Shodan/LeakIX web scrape, manual seed)
- Real validation (actual generation test, not just port check)
- WebUI control panel: view nodes/models, trigger/stop scan, add manual entries
"""
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import sqlite3, threading, pathlib, os
import requests
from contextlib import asynccontextmanager
from pydantic import BaseModel

import scanner

DATABASE = "opencompute.db"
WEBUI_PATH = pathlib.Path(__file__).parent / "webui.html"
DEFAULT_API_KEY = os.getenv("OPENCOMPUTE_API_KEY", "sk-1234")

def get_api_key():
    return scanner.get_setting("api_key", DEFAULT_API_KEY)

def check_api_key(authorization: str = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing API key. Use: Authorization: Bearer <key>")
    token = authorization.removeprefix("Bearer ").strip()
    if token != get_api_key():
        raise HTTPException(401, "Invalid API key")
    return True

def db():
    conn = sqlite3.connect(DATABASE, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    scanner.init_db()
    print("✅ Database ready")
    # Auto-resume on every process start (systemd restart, reboot, crash
    # recovery) so a masscan-only 24/7 deployment never needs a human to
    # notice it stopped and manually restart it. masscan resumes from
    # paused.conf when present (or starts fresh on first-ever boot); the
    # continuous scan loop is idempotent to call every start.
    if scanner.get_enabled_sources().get("masscan", True):
        try:
            r = scanner.start_masscan()
            print(f"🛰 masscan auto-start: {r.get('message')}")
        except Exception as e:
            print(f"⚠️ masscan auto-start failed: {e}")
    try:
        interval = int(scanner.get_setting("continuous_interval", 180))
        if scanner.start_continuous(interval_seconds=interval):
            print(f"🔁 continuous scan auto-started (interval={interval}s)")
    except Exception as e:
        print(f"⚠️ continuous scan auto-start failed: {e}")
    yield
    # ── Graceful shutdown ──────────────────────────────────────────
    # Without this, SIGTERM only tears down the asyncio/uvicorn side —
    # the long-lived masscan child process (raw sockets, its own signal
    # handling) is left running as a sibling in the same process/cgroup.
    # systemd then waits for the whole cgroup to empty, times out after
    # TimeoutStopSec, and SIGKILLs everything (losing masscan's chance to
    # write its --resume checkpoint cleanly). Stopping it here — SIGINT so
    # masscan saves paused.conf — lets the process actually exit on its own
    # well within systemd's stop timeout.
    print("🛑 shutting down — stopping continuous scan + masscan...")
    try:
        scanner.stop_continuous()
    except Exception as e:
        print(f"⚠️ error stopping continuous scan/masscan on shutdown: {e}")
    print("✅ shutdown cleanup done — forcing immediate exit")
    # Python's normal interpreter exit waits (via an internal atexit hook) for
    # every concurrent.futures.ThreadPoolExecutor worker thread to finish —
    # these are NOT daemon threads. If a validation round's threadpool has a
    # worker mid-request against a slow/unreachable node (up to ~45s timeout),
    # process exit blocks on that join even though the important cleanup
    # (masscan SIGINT + resume checkpoint saved) already happened above. Rather
    # than risk creeping back up to systemd's TimeoutStopSec, hard-exit now —
    # everything that matters for a clean resume is already on disk.
    os._exit(0)

app = FastAPI(title="OpenCompute")
app.router.lifespan_context = lifespan
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
STATIC_DIR = pathlib.Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

def _proto(port):
    return "https" if port == 443 else "http"

# ── OpenAI-compatible API ──────────────────────────────────────────

@app.get("/v1/models")
async def list_models(_ok: bool = Depends(check_api_key)):
    conn = db()
    models = conn.execute(
        """SELECT DISTINCT m.model_name, COUNT(*) as node_count,
                  MAX(m.param_size_b) as param_size_b, MAX(m.is_big) as is_big
           FROM models m JOIN nodes n ON m.node_id = n.id
           WHERE m.working = 1 AND n.archived = 0
           GROUP BY m.model_name ORDER BY is_big DESC, param_size_b DESC, node_count DESC"""
    ).fetchall()
    conn.close()
    return {"object": "list", "data": [
        {"id": m["model_name"], "object": "model", "owned_by": "opencompute",
         "node_count": m["node_count"], "param_size_b": m["param_size_b"],
         "big": bool(m["is_big"])} for m in models]}

# In-memory round-robin cursor per model — spreads load across all known-working
# nodes for that model instead of always hammering the same "lowest latency" one,
# and means a node that's currently down gets skipped in favor of the next in
# rotation rather than blocking every request behind it.
_rr_cursor: dict = {}

@app.post("/v1/chat/completions")
async def chat_completions(request: dict, _ok: bool = Depends(check_api_key)):
    model = request.get("model")
    messages = request.get("messages", [])
    if not model or not messages:
        raise HTTPException(400, "model and messages required")

    conn = db()
    nodes = conn.execute(
        """SELECT n.id, n.host, n.port, n.scheme FROM nodes n
           JOIN models m ON n.id = m.node_id
           WHERE m.model_name = ? AND m.working = 1 AND n.archived = 0
           ORDER BY n.latency_ms ASC""", (model,)).fetchall()
    conn.close()
    if not nodes:
        raise HTTPException(404, f"Model not found or not verified working: {model}")

    nodes = list(nodes)
    # rotate the start point so consecutive requests for this model don't all
    # hit the same first node — spreads load and quickly routes around any
    # node that's currently down without needing every request to retry it
    start = _rr_cursor.get(model, 0) % len(nodes)
    ordered = nodes[start:] + nodes[:start]
    _rr_cursor[model] = (start + 1) % len(nodes)
    # cap how many nodes a single request will try — with rotation, a node
    # that's skipped this time gets tried first on a future request, so we
    # still cover every node for the model over time without one slow/dead
    # request having to exhaust hundreds of them serially
    max_attempts = min(len(ordered), 20)
    ordered = ordered[:max_attempts]

    last_err = None
    dead_ids = []
    for node in ordered:
        scheme = node["scheme"] or _proto(node["port"])
        try:
            resp = requests.post(
                f"{scheme}://{node['host']}:{node['port']}/v1/chat/completions",
                json={"model": model, "messages": messages, "stream": False},
                headers={"User-Agent": "Mozilla/5.0"}, timeout=(5, 45))
            if resp.status_code == 200:
                return resp.json()
            last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = str(e)
            dead_ids.append((str(e)[:200], node["id"]))
    if dead_ids:
        try:
            c = db()
            c.executemany("UPDATE nodes SET status='dead', error=? WHERE id=?", dead_ids)
            c.commit(); c.close()
        except Exception:
            pass
    raise HTTPException(502, f"All {len(nodes)} node(s) for this model failed. Last error: {last_err}")

# ── Control API ──────────────────────────────────────────────────

@app.get("/api/nodes")
async def list_nodes(status: str = None, include_archived: bool = False):
    conn = db()
    q = "SELECT * FROM nodes"
    conds = []
    args = []
    if not include_archived:
        conds.append("archived = 0")
    if status:
        conds.append("status = ?")
        args.append(status)
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY status DESC, latency_ms ASC LIMIT 300"
    nodes = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(n) for n in nodes]

@app.get("/api/nodes/archived")
async def list_archived_nodes():
    """Nodes that were automatically archived — every model we tested on them
    responded with a credit/quota/paid-API-key message instead of a real answer.
    Kept visible for manual review but excluded from /v1/models and chat routing."""
    conn = db()
    nodes = conn.execute(
        """SELECT * FROM nodes WHERE archived = 1
           ORDER BY last_check DESC LIMIT 300""").fetchall()
    conn.close()
    return [dict(n) for n in nodes]

@app.post("/api/nodes/{node_id:path}/unarchive")
async def unarchive_node(node_id: str):
    """Manually restore an archived node back into active rotation (e.g. if you
    believe the credit-required detection was a false positive)."""
    conn = db()
    conn.execute("UPDATE nodes SET archived = 0, archive_reason = NULL WHERE id = ?", (node_id,))
    conn.commit(); conn.close()
    return {"ok": True}

@app.get("/api/models")
async def list_all_models(include_archived: bool = False, working_only: bool = True, expand: bool = False):
    """By default: only real, currently-working models (working=1), one row per
    model with an aggregated node_count — NOT one row per (model, node) pair.
    Pass expand=true to get the flat per-node breakdown (e.g. to pick which
    specific node to hit, or to see why a model failed via fail_reason), or
    working_only=false to also see untested/dead candidates."""
    conn = db()
    if expand:
        q = """SELECT m.id as model_row_id, m.model_name, m.working, m.param_size_b, m.is_big,
                      m.fail_reason, m.last_error, m.last_tested,
                      n.id as node_id, n.host, n.port, n.scheme, n.status, n.source, n.archived, n.archive_reason
               FROM models m JOIN nodes n ON m.node_id = n.id"""
        conds = []
        if not include_archived:
            conds.append("n.archived = 0")
        if working_only:
            conds.append("m.working = 1")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY m.is_big DESC, m.param_size_b DESC, m.model_name"
        rows = conn.execute(q).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    q = """SELECT m.model_name, MAX(m.param_size_b) as param_size_b, MAX(m.is_big) as is_big,
                  COUNT(DISTINCT n.id) as node_count,
                  GROUP_CONCAT(DISTINCT n.source) as sources
           FROM models m JOIN nodes n ON m.node_id = n.id"""
    conds = []
    if not include_archived:
        conds.append("n.archived = 0")
    if working_only:
        conds.append("m.working = 1")
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " GROUP BY m.model_name ORDER BY is_big DESC, param_size_b DESC, node_count DESC"
    rows = conn.execute(q).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/models/failed")
async def list_failed_models(reason: str = None):
    """Models that aren't currently working, grouped with their fail_reason so
    the UI can show a badge: 'temporarily unavailable' (worth a manual retest —
    OOM/model-loading/node-briefly-down) vs 'confirmed fake' (honeypot/echo-bot,
    not worth retrying)."""
    conn = db()
    q = """SELECT m.id as model_row_id, m.model_name, m.fail_reason, m.last_error, m.last_tested,
                  n.id as node_id, n.host, n.port, n.scheme, n.status, n.source
           FROM models m JOIN nodes n ON m.node_id = n.id
           WHERE m.working = 0 AND n.archived = 0"""
    args = []
    if reason:
        q += " AND m.fail_reason = ?"
        args.append(reason)
    q += " ORDER BY m.last_tested DESC LIMIT 500"
    rows = conn.execute(q, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]

class RetestModel(BaseModel):
    node_id: str
    model_name: str

@app.post("/api/models/retest")
async def retest_one_model(body: RetestModel):
    """Manually re-run the real-generation test for one specific (node, model)
    pair right now — e.g. a node that failed with 'temp_unavailable' (OOM /
    still loading) a few minutes ago might have recovered. Runs in FastAPI's
    threadpool since scanner.retest_model() makes a blocking HTTP call."""
    from starlette.concurrency import run_in_threadpool
    result = await run_in_threadpool(scanner.retest_model, body.node_id, body.model_name)
    return result

_retest_state = {"running": False, "checked": 0, "recovered": 0, "total": 0}

@app.post("/api/models/retest-failed")
async def retest_all_failed():
    """Kick off a bulk-retest of every model whose last failure looks transient
    (OOM, node briefly down, timeout) rather than confirmed-fake. Runs in a
    background thread (like the scanner) so it doesn't block the API/dashboard
    while potentially hundreds of nodes are being re-checked — poll
    /api/models/retest-status for progress."""
    if _retest_state["running"]:
        return {"status": "already_running", **_retest_state}
    def _run():
        _retest_state.update({"running": True, "checked": 0, "recovered": 0, "total": 0})
        try:
            result = scanner.retest_failed_models()
            _retest_state.update(checked=result["checked"], recovered=result["recovered"])
        finally:
            _retest_state["running"] = False
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started"}

@app.get("/api/models/retest-status")
async def retest_status():
    return dict(_retest_state)

@app.get("/api/stats")
async def stats():
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM nodes WHERE archived=0").fetchone()["c"]
    verified = conn.execute("SELECT COUNT(*) c FROM nodes WHERE status='verified' AND archived=0").fetchone()["c"]
    alive = conn.execute("SELECT COUNT(*) c FROM nodes WHERE status='alive' AND archived=0").fetchone()["c"]
    archived = conn.execute("SELECT COUNT(*) c FROM nodes WHERE archived=1").fetchone()["c"]
    working_models = conn.execute(
        "SELECT COUNT(DISTINCT m.model_name) c FROM models m JOIN nodes n ON m.node_id=n.id WHERE m.working=1 AND n.archived=0").fetchone()["c"]
    total_models = conn.execute(
        "SELECT COUNT(DISTINCT m.model_name) c FROM models m JOIN nodes n ON m.node_id=n.id WHERE n.archived=0").fetchone()["c"]
    big_models = conn.execute(
        "SELECT COUNT(DISTINCT m.model_name) c FROM models m JOIN nodes n ON m.node_id=n.id WHERE m.working=1 AND m.is_big=1 AND n.archived=0").fetchone()["c"]
    last = conn.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    state = scanner.get_state()
    state["continuous"] = scanner.is_continuous_running()
    try:
        state["masscan"] = scanner.masscan_status()
    except Exception:
        pass
    return {"total_nodes": total, "verified": verified, "alive": alive, "archived": archived,
            "working_models": working_models, "total_models": total_models,
            "big_models": big_models,
            "last_scan": dict(last) if last else None, "scan_state": state}

@app.get("/api/stats/sources")
async def stats_sources(include_archived: bool = False):
    """Breakdown of nodes/working-models per discovery source, for the dashboard chart
    and for the source filter dropdowns in the Nodes/Models tabs."""
    conn = db()
    q = "SELECT source, status, archived FROM nodes"
    if not include_archived:
        q += " WHERE archived = 0"
    rows = conn.execute(q).fetchall()

    mq = """SELECT n.source, m.working FROM models m JOIN nodes n ON m.node_id = n.id"""
    if not include_archived:
        mq += " WHERE n.archived = 0"
    model_rows = conn.execute(mq).fetchall()
    conn.close()

    node_counts = {}
    for r in rows:
        base = scanner.source_base(r["source"])
        d = node_counts.setdefault(base, {"total": 0, "verified": 0, "alive": 0})
        d["total"] += 1
        if r["status"] == "verified":
            d["verified"] += 1
        elif r["status"] == "alive":
            d["alive"] += 1

    model_counts = {}
    for r in model_rows:
        base = scanner.source_base(r["source"])
        d = model_counts.setdefault(base, {"total": 0, "working": 0})
        d["total"] += 1
        if r["working"]:
            d["working"] += 1

    sources = set(node_counts) | set(model_counts) | set(scanner.DEFAULT_SOURCES)
    result = []
    for s in sorted(sources):
        nc = node_counts.get(s, {"total": 0, "verified": 0, "alive": 0})
        mc = model_counts.get(s, {"total": 0, "working": 0})
        result.append({"source": s, "nodes_total": nc["total"], "nodes_verified": nc["verified"],
                        "nodes_alive": nc["alive"], "models_total": mc["total"], "models_working": mc["working"]})
    return result

# ── Settings ────────────────────────────────────────────────────────

@app.get("/api/settings/sources")
async def get_source_settings():
    return scanner.get_enabled_sources()

class SourceSettings(BaseModel):
    sources: dict

@app.post("/api/settings/sources")
async def update_source_settings(body: SourceSettings):
    return scanner.set_enabled_sources(body.sources)

class ApiKeyUpdate(BaseModel):
    api_key: str

@app.get("/api/settings/api-key")
async def get_api_key_setting():
    return {"api_key": get_api_key()}

@app.post("/api/settings/api-key")
async def set_api_key_setting(body: ApiKeyUpdate):
    new_key = body.api_key.strip()
    if not new_key:
        raise HTTPException(400, "API key cannot be empty")
    scanner.set_setting("api_key", new_key)
    return {"ok": True, "api_key": new_key}

class LeakixKeyUpdate(BaseModel):
    leakix_api_key: str

@app.get("/api/settings/leakix-key")
async def get_leakix_key_setting():
    return {"leakix_api_key": scanner.get_setting("leakix_api_key", "") or ""}

@app.post("/api/settings/leakix-key")
async def set_leakix_key_setting(body: LeakixKeyUpdate):
    scanner.set_setting("leakix_api_key", body.leakix_api_key.strip())
    return {"ok": True}

# ── Per-source scanner API keys ──────────────────────────────────────
# Every discovery source that needs a key (Shodan, LeakIX, Censys, ...) is
# tested for real before being saved. The source stays visible/toggleable in
# Settings regardless, but build_candidates() only calls sources whose key
# actually validated (see scanner.py get_source_api_key()).

@app.get("/api/settings/scanner-keys")
async def list_scanner_keys():
    """Which sources need a key, whether one is currently configured, and a
    masked preview so the UI can show 'sk-...abcd' instead of the raw value."""
    result = {}
    for source, meta in scanner.API_KEY_SOURCES.items():
        val = scanner.get_source_api_key(source) or ""
        result[source] = {
            "label": meta["label"],
            "configured": bool(val),
            "masked": (val[:4] + "…" + val[-4:]) if len(val) > 10 else ("•" * len(val) if val else ""),
        }
    return result

class ScannerKeyTest(BaseModel):
    source: str  # "shodan" | "leakix" | "censys"
    key: str = ""          # shodan / leakix
    api_id: str = ""       # censys
    api_secret: str = ""   # censys

@app.post("/api/settings/scanner-keys/test")
async def test_scanner_key(body: ScannerKeyTest):
    """Test a scanner source's API key with one cheap real call. Only saves it
    (persists to the DB) if the test succeeds — never stores an unverified key."""
    if body.source == "shodan":
        ok, msg = scanner.test_api_key("shodan", key=body.key.strip())
    elif body.source == "leakix":
        ok, msg = scanner.test_api_key("leakix", key=body.key.strip())
    elif body.source == "censys":
        ok, msg = scanner.test_api_key("censys", api_id=body.api_id.strip(), api_secret=body.api_secret.strip())
    else:
        raise HTTPException(400, f"unknown source: {body.source}")
    return {"ok": ok, "message": msg}

@app.delete("/api/settings/scanner-keys/{source}")
async def clear_scanner_key(source: str):
    """Remove a configured scanner API key (source auto-disables until a new key is set)."""
    if source == "censys":
        scanner.set_api_key("censys_id", "")
        scanner.set_api_key("censys_secret", "")
    elif source in scanner.API_KEY_SOURCES:
        scanner.set_api_key(source, "")
    else:
        raise HTTPException(400, f"unknown source: {source}")
    return {"ok": True}

class ContinuousIntervalUpdate(BaseModel):
    interval_seconds: int

@app.get("/api/settings/continuous-interval")
async def get_continuous_interval():
    return {"interval_seconds": int(scanner.get_setting("continuous_interval", 180))}

@app.post("/api/settings/continuous-interval")
async def set_continuous_interval(body: ContinuousIntervalUpdate):
    if body.interval_seconds < 30:
        raise HTTPException(400, "interval_seconds must be >= 30")
    scanner.set_setting("continuous_interval", str(body.interval_seconds))
    return {"ok": True, "interval_seconds": body.interval_seconds}

# ── Masscan (internet-wide raw-socket sweep) ─────────────────────────

@app.get("/api/masscan/status")
async def masscan_status():
    """Current sweep state: running, pid, % of 0.0.0.0/0 done, open ports found."""
    return scanner.masscan_status()

@app.post("/api/masscan/start")
async def masscan_start():
    return scanner.start_masscan()

@app.post("/api/masscan/stop")
async def masscan_stop():
    return scanner.stop_masscan()

class MasscanConfigUpdate(BaseModel):
    target: str | None = None
    rate: int | None = None
    ports: str | None = None
    excludes: str | None = None

@app.get("/api/settings/masscan")
async def get_masscan_settings():
    return scanner.get_masscan_config()

@app.post("/api/settings/masscan")
async def set_masscan_settings(body: MasscanConfigUpdate):
    return scanner.set_masscan_config(target=body.target, rate=body.rate,
                                      ports=body.ports, excludes=body.excludes)

@app.post("/api/scan/start")
async def start_scan(include_seed: bool = True):
    if scanner.get_state()["running"]:
        return {"status": "already_running"}
    def _run():
        try:
            scanner.full_scan(include_manual_seed=include_seed)
        except Exception as e:
            print(f"Scan error: {e}")
    threading.Thread(target=_run, daemon=True).start()
    return {"status": "started"}

@app.post("/api/scan/stop")
async def stop_scan():
    scanner.stop_scan()
    return {"status": "stopping"}

@app.post("/api/scan/continuous/start")
async def start_continuous_scan(interval_seconds: int = None):
    if interval_seconds is None:
        interval_seconds = int(scanner.get_setting("continuous_interval", 180))
    started = scanner.start_continuous(interval_seconds=interval_seconds)
    return {"status": "started" if started else "already_running"}

@app.post("/api/scan/continuous/stop")
async def stop_continuous_scan():
    scanner.stop_continuous()
    return {"status": "stopped"}

@app.get("/api/scan/status")
async def scan_status():
    state = scanner.get_state()
    state["continuous"] = scanner.is_continuous_running()
    return state

class ManualAdd(BaseModel):
    target: str  # IP, host, host:port, or full URL

@app.post("/api/nodes/add")
async def add_node(body: ManualAdd):
    result = scanner.add_manual(body.target)
    return result

@app.delete("/api/nodes/{node_id:path}")
async def delete_node(node_id: str):
    conn = db()
    conn.execute("DELETE FROM models WHERE node_id = ?", (node_id,))
    conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    conn.commit(); conn.close()
    return {"ok": True}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/models", response_class=HTMLResponse)
async def models_viewer():
    """Plain browser-viewable model list — no Authorization header needed.
    (The /v1/models JSON API still requires the API key; this is just a
    human-readable page so you can see the list without curl/Postman.)"""
    conn = db()
    models = conn.execute(
        """SELECT DISTINCT m.model_name, COUNT(*) as node_count,
                  MAX(m.param_size_b) as param_size_b, MAX(m.is_big) as is_big
           FROM models m JOIN nodes n ON m.node_id = n.id
           WHERE m.working = 1 AND n.archived = 0
           GROUP BY m.model_name ORDER BY is_big DESC, param_size_b DESC, node_count DESC"""
    ).fetchall()
    conn.close()
    rows_html = "".join(
        f"<tr><td>{'💪 ' if m['is_big'] else ''}{m['model_name']}</td>"
        f"<td>{(str(m['param_size_b']) + 'B') if m['param_size_b'] else '-'}</td>"
        f"<td>{m['node_count']}</td></tr>"
        for m in models
    ) or "<tr><td colspan='3'>No verified models yet</td></tr>"
    return f"""<!DOCTYPE html><html lang="en" dir="ltr"><head><meta charset="UTF-8">
<title>OpenCompute Models</title>
<style>
body{{font-family:'JetBrains Mono',monospace;background:#041c1c;color:#eafff4;padding:24px}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:8px 12px;border-bottom:1px solid #123832;text-align:left}}
th{{color:#4ade80}} a{{color:#4ade80}}
</style></head><body>
<p><a href="/">← Back to dashboard</a></p>
<h1>Active Models ({len(models)})</h1>
<table><thead><tr><th>Model</th><th>Size</th><th>Node Count</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</body></html>"""

@app.get("/nodes", response_class=HTMLResponse)
async def nodes_viewer():
    """Plain browser-viewable node list — no Authorization header needed."""
    conn = db()
    nodes = conn.execute(
        "SELECT * FROM nodes WHERE archived=0 ORDER BY status DESC, latency_ms ASC LIMIT 300").fetchall()
    conn.close()
    rows_html = "".join(
        f"<tr><td>{n['scheme'] or 'http'}://{n['host']}:{n['port']}</td>"
        f"<td>{n['status']}</td><td>{n['model_count']}</td>"
        f"<td>{n['latency_ms'] or '-'}ms</td><td>{n['source'] or '-'}</td></tr>"
        for n in nodes
    ) or "<tr><td colspan='5'>No nodes found yet</td></tr>"
    return f"""<!DOCTYPE html><html lang="en" dir="ltr"><head><meta charset="UTF-8">
<title>OpenCompute Nodes</title>
<style>
body{{font-family:'JetBrains Mono',monospace;background:#041c1c;color:#eafff4;padding:24px}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:8px 12px;border-bottom:1px solid #123832;text-align:left}}
th{{color:#4ade80}} a{{color:#4ade80}}
</style></head><body>
<p><a href="/">← Back to dashboard</a></p>
<h1>Nodes ({len(nodes)})</h1>
<table><thead><tr><th>Host:Port</th><th>Status</th><th>Models</th><th>Latency</th><th>Source</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</body></html>"""

# ── WebUI ──────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def webui():
    return WEBUI_PATH.read_text(encoding="utf-8")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5555)
