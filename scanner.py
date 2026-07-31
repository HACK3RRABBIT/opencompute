#!/usr/bin/env python3
"""
OpenCompute Scanner v2 — minimal-bandwidth passive discovery + real validation
Sources (no API key required):
  - Manual seed list (user-provided)
  - crt.sh (certificate transparency)
  - HackerTarget (subdomain enum)
  - Shodan web search HTML scrape (public search page, no key)
  - LeakIX web search HTML scrape (public search page, no key)
Validation chain per candidate (~2-5KB total):
  1. TCP connect check
  2. GET /v1/models (or /api/tags fallback) -> list model names
  3. Real generation test on first model -> proves it actually answers
"""
import sqlite3, socket, json, re, threading, time, os, random, string
import concurrent.futures as cf
import requests

DB = "opencompute.db"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUTS = {"tcp": 3, "probe": 6, "gen": 15}

# Paid/proprietary model names we never want to list — these run through a gateway
# that bills a real API key (OpenAI/Anthropic/Google/etc). Even if a node proxies them,
# we can't guarantee free access, so we exclude them entirely from candidacy.
PAID_MODEL_PATTERNS = re.compile(
    r"^(gpt-3\.5|gpt-4|gpt-4o|o1|o3|o4|text-embedding|text-davinci|davinci|"
    r"claude|gemini|grok|mistral-large|mistral-medium|command-r|command-a|"
    r"dall-e|whisper-1|tts-1)", re.I
)

def is_paid_model(name: str) -> bool:
    return bool(PAID_MODEL_PATTERNS.match(name.strip()))

# ── SETTINGS (persisted, toggle which discovery sources run) ───────

DEFAULT_SOURCES = {
    "crtsh": True,
    "certspotter": True,
    "hackertarget": True,
    "shodan_web": True,
    "shodan_api": True,
    "leakix": True,
    "censys": True,
    "port_sweep": True,
    "manual_seed": True,
}

def get_setting(key, default=None):
    with db() as c:
        row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

def set_setting(key, value):
    with db() as c:
        c.execute("""INSERT INTO settings (key, value) VALUES (?, ?)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value""", (key, value))

def get_enabled_sources():
    raw = get_setting("enabled_sources")
    if raw is None:
        return dict(DEFAULT_SOURCES)
    try:
        parsed = json.loads(raw)
        merged = dict(DEFAULT_SOURCES)
        merged.update(parsed)
        return merged
    except Exception:
        return dict(DEFAULT_SOURCES)

def set_enabled_sources(sources: dict):
    merged = get_enabled_sources()
    merged.update({k: bool(v) for k, v in sources.items() if k in DEFAULT_SOURCES})
    set_setting("enabled_sources", json.dumps(merged))
    return merged

def source_base(source_str: str) -> str:
    """Normalize a stored 'source' value like 'crt.sh:foo.com' or 'leakix:1.2.3.4'
    down to a stable category key used for filtering/stats (matches DEFAULT_SOURCES keys)."""
    if not source_str:
        return "unknown"
    s = source_str.split(":", 1)[0].lower()
    mapping = {
        "crt.sh": "crtsh", "certspotter": "certspotter", "hackertarget": "hackertarget",
        "shodan-web": "shodan_web", "shodan-api": "shodan_api", "leakix": "leakix",
        "censys": "censys", "port-sweep": "port_sweep",
        "user-seed": "manual_seed", "manual": "manual_seed",
    }
    return mapping.get(s, s)

# ── PER-SOURCE API KEYS ──────────────────────────────────────────────
# Sources that need a user-supplied API key. Each entry maps the source key
# (matches DEFAULT_SOURCES) to a settings key name and a "tester" function
# that makes one cheap real call to confirm the key actually works before we
# let the user turn that source on. Add a new source here + a test_* function
# to support another provider (Censys, VirusTotal, etc.) later.

API_KEY_SOURCES = {
    "shodan": {"setting_key": "shodan_api_key", "label": "Shodan"},
    "leakix": {"setting_key": "leakix_api_key", "label": "LeakIX"},
    "censys_id": {"setting_key": "censys_api_id", "label": "Censys (API ID)"},
    "censys_secret": {"setting_key": "censys_api_secret", "label": "Censys (API Secret)"},
}

def get_source_api_key(source: str) -> str:
    meta = API_KEY_SOURCES.get(source)
    if not meta:
        return ""
    return get_setting(meta["setting_key"], "") or ""

def set_api_key(source: str, value: str):
    meta = API_KEY_SOURCES.get(source)
    if not meta:
        raise ValueError(f"unknown API key source: {source}")
    set_setting(meta["setting_key"], value.strip())

def test_shodan_key(key: str):
    """Cheap Shodan call — /api-info costs 0 query credits."""
    try:
        r = requests.get("https://api.shodan.io/api-info", params={"key": key}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return True, f"OK — plan: {data.get('plan', '?')}, query credits: {data.get('query_credits', 0)}"
        if r.status_code == 401:
            return False, "Invalid API key"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def test_leakix_key(key: str):
    """Cheap LeakIX call — tiny 1-result search."""
    try:
        r = requests.get("https://leakix.net/search",
            params={"scope": "leak", "q": "port:11434 ollama", "page": 0},
            headers={"api-key": key, "Accept": "application/json", "User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            return True, "OK"
        if r.status_code in (401, 403):
            return False, "Invalid API key"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def test_censys_key(api_id: str, api_secret: str):
    """Cheap Censys call — tiny 1-result host search."""
    try:
        r = requests.get("https://search.censys.io/api/v2/hosts/search",
            params={"q": "services.port: 11434", "per_page": 1},
            auth=(api_id, api_secret), timeout=10)
        if r.status_code == 200:
            return True, "OK"
        if r.status_code in (401, 403):
            return False, "Invalid API key"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def test_api_key(source: str, **kwargs):
    """Dispatch to the right tester and, on success, persist the key(s)."""
    if source == "shodan":
        key = kwargs.get("key", "")
        ok, msg = test_shodan_key(key)
        if ok:
            set_api_key("shodan", key)
        return ok, msg
    if source == "leakix":
        key = kwargs.get("key", "")
        ok, msg = test_leakix_key(key)
        if ok:
            set_api_key("leakix", key)
        return ok, msg
    if source == "censys":
        api_id = kwargs.get("api_id", "")
        api_secret = kwargs.get("api_secret", "")
        ok, msg = test_censys_key(api_id, api_secret)
        if ok:
            set_api_key("censys_id", api_id)
            set_api_key("censys_secret", api_secret)
        return ok, msg
    return False, f"unknown source: {source}"

_stop_flag = threading.Event()
_scan_state = {"running": False, "phase": "", "found": 0, "verified": 0, "checked": 0, "total": 0}

def db():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL,
            scheme TEXT DEFAULT 'http', source TEXT, status TEXT DEFAULT 'unknown',
            model_count INTEGER DEFAULT 0, latency_ms INTEGER,
            verified_at DATETIME, last_check DATETIME, added_by TEXT DEFAULT 'scanner',
            error TEXT, archived INTEGER DEFAULT 0, archive_reason TEXT,
            UNIQUE(host, port))""")
        c.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS models (
            id TEXT PRIMARY KEY, node_id TEXT NOT NULL, model_name TEXT NOT NULL,
            working INTEGER DEFAULT 0, last_tested DATETIME,
            param_size_b REAL DEFAULT 0, is_big INTEGER DEFAULT 0,
            FOREIGN KEY(node_id) REFERENCES nodes(id), UNIQUE(node_id, model_name))""")
        c.execute("""CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT, found INTEGER, verified INTEGER)""")
        # Tracks response fingerprints (system_fingerprint / server headers / etc.)
        # seen per host, so we can detect the same "unique" backend signature
        # showing up across many unrelated IPs — a strong honeypot-farm signal.
        c.execute("""CREATE TABLE IF NOT EXISTS fingerprints (
            fingerprint TEXT NOT NULL, host TEXT NOT NULL, model_name TEXT NOT NULL,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (fingerprint, host, model_name))""")
        # migrate older DBs that predate these columns
        cols = {row[1] for row in c.execute("PRAGMA table_info(models)")}
        if "param_size_b" not in cols:
            c.execute("ALTER TABLE models ADD COLUMN param_size_b REAL DEFAULT 0")
        if "is_big" not in cols:
            c.execute("ALTER TABLE models ADD COLUMN is_big INTEGER DEFAULT 0")
        node_cols = {row[1] for row in c.execute("PRAGMA table_info(nodes)")}
        if "archived" not in node_cols:
            c.execute("ALTER TABLE nodes ADD COLUMN archived INTEGER DEFAULT 0")
        if "archive_reason" not in node_cols:
            c.execute("ALTER TABLE nodes ADD COLUMN archive_reason TEXT")

# Big/powerful open-weight model families worth prioritizing (name-based hint,
# used together with parsed parameter-count when the API reports it).
BIG_MODEL_NAME_HINTS = re.compile(
    r"(glm[-_]?[45]|glm[-_]?5\.2|deepseek[-_]?(r1|v3)|qwen2?\.?5?[-_]?(72|110|235)b|"
    r"llama[-_]?3\.[13]?[-_]?70b|llama[-_]?3\.1[-_]?405b|mixtral[-_]?8x22b|"
    r"command[-_]?r\+|dbrx|grok-1|kimi[-_]?k2)", re.I
)

_SIZE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*[bB](?!yte)")

def parse_param_size(model_name: str, details_param_size: str = None) -> float:
    """Best-effort parameter count in billions, from Ollama 'parameter_size' field
    or parsed out of the model name itself (e.g. 'llama3.1:70b' -> 70)."""
    if details_param_size:
        m = _SIZE_RE.search(str(details_param_size))
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    m = _SIZE_RE.search(model_name)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return 0.0

def is_big_model(model_name: str, param_size_b: float) -> bool:
    if param_size_b and param_size_b >= 32:
        return True
    return bool(BIG_MODEL_NAME_HINTS.search(model_name))

# ── DISCOVERY (passive / free, minimal bandwidth) ──────────────────

def discover_crtsh():
    out = set()
    for q in ("%ollama%", "%open-webui%", "%litellm%", "%llama%", "%vllm%", "%textgen%", "%lmstudio%"):
        try:
            r = requests.get(f"https://crt.sh/?q={q}&output=json",
                             headers={"User-Agent": UA}, timeout=25)
            if r.status_code == 200:
                for e in r.json():
                    for name in (e.get("name_value") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and re.fullmatch(r"[\w.-]+\.\w{2,}", name) and "ollama.com" not in name:
                            out.add(name)
        except Exception:
            pass
    return out

def discover_certspotter():
    """Certificate transparency via CertSpotter — cheap, ~10KB per base domain."""
    out = set()
    for base in ("ollama.com",):
        try:
            r = requests.get("https://api.certspotter.com/v1/issuances",
                params={"domain": base, "include_subdomains": "true", "expand": "dns_names"},
                headers={"User-Agent": UA}, timeout=15)
            if r.status_code == 200:
                for e in r.json():
                    for name in e.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name and name != base and re.fullmatch(r"[\w.-]+\.\w{2,}", name):
                            out.add(name)
        except Exception:
            pass
    return out

def discover_hackertarget():
    out = set()
    for base in ("ollama.com",):
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={base}",
                             headers={"User-Agent": UA}, timeout=15)
            for line in r.text.strip().splitlines():
                host = line.split(",")[0].strip().lower()
                if host and host != base and "ollama.com" not in host:
                    out.add(host)
        except Exception:
            pass
    return out

def discover_shodan_web(pages=2):
    """Scrape Shodan's public search HTML (no API key) for several open-model queries.
    This always runs regardless of whether a Shodan API key is configured — it's free."""
    out = set()
    queries = [
        "port:11434 ollama", "\"ollama is running\"", "port:8080 open-webui",
        "port:7860 gradio", "port:1234 \"lm studio\"", "port:8000 vllm",
        "port:5000 \"text generation web ui\"",
    ]
    for q in queries:
        for p in range(1, pages + 1):
            try:
                r = requests.get("https://www.shodan.io/search",
                    params={"query": q, "page": p},
                    headers={"User-Agent": UA}, timeout=15)
                if r.status_code != 200:
                    break
                ips = set(re.findall(r'href="/host/(\d+\.\d+\.\d+\.\d+)"', r.text))
                if not ips:
                    break
                out |= ips
            except Exception:
                break
    return out

def discover_shodan_api(max_results=100):
    """Real Shodan Search API — used only if the user has configured a Shodan API
    key in Settings. Much richer than the free web-scrape (full search + facets),
    and consumes Shodan query credits, hence opt-in via key."""
    out = set()
    api_key = get_source_api_key("shodan")
    if not api_key:
        return out
    queries = ["port:11434 ollama", "port:8080 open-webui", "port:7860 gradio"]
    for q in queries:
        try:
            r = requests.get("https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": q, "limit": max_results}, timeout=20)
            if r.status_code != 200:
                continue
            data = r.json()
            for match in data.get("matches", []):
                ip = match.get("ip_str")
                port = match.get("port")
                if ip and port:
                    out.add((ip, int(port)))
        except Exception:
            continue
    return out

def discover_censys(max_pages=3, per_page=50):
    """Real Censys Search API v2 — used only if the user has configured Censys
    API ID + Secret in Settings. Returns (host, port) tuples."""
    out = set()
    api_id = get_source_api_key("censys_id")
    api_secret = get_source_api_key("censys_secret")
    if not api_id or not api_secret:
        return out
    queries = ["services.port: 11434", "services.port: 8080 and services.service_name: HTTP"]
    for q in queries:
        cursor = None
        for _ in range(max_pages):
            try:
                params = {"q": q, "per_page": per_page}
                if cursor:
                    params["cursor"] = cursor
                r = requests.get("https://search.censys.io/api/v2/hosts/search",
                    params=params, auth=(api_id, api_secret), timeout=20)
                if r.status_code != 200:
                    break
                data = r.json()
                hits = data.get("result", {}).get("hits", [])
                if not hits:
                    break
                for hit in hits:
                    ip = hit.get("ip")
                    for svc in hit.get("services", []):
                        port = svc.get("port")
                        if ip and port:
                            out.add((ip, int(port)))
                cursor = data.get("result", {}).get("links", {}).get("next")
                if not cursor:
                    break
            except Exception:
                break
    return out

LEAKIX_API_KEY = os.getenv("LEAKIX_API_KEY", "")

def discover_leakix(max_pages=10, page_size=20):
    """Real LeakIX API search — finds exposed Ollama instances directly (host, port, scheme).
    Cheap: each page is ~5-10KB of JSON. Returns a set of (host, port, scheme) tuples.
    Requires a free LeakIX API key (leakix.net) configured via the Settings tab (or
    LEAKIX_API_KEY env var as a fallback) — silently skipped if not configured."""
    out = set()
    api_key = get_source_api_key("leakix") or LEAKIX_API_KEY
    if not api_key:
        return out
    queries = [
        '+event_source:"OllamaPlugin"',
        'port:11434 ollama',
    ]
    for q in queries:
        for page in range(max_pages):
            try:
                r = requests.get("https://leakix.net/search",
                    params={"scope": "leak", "q": q, "page": page},
                    headers={"api-key": api_key, "Accept": "application/json", "User-Agent": UA},
                    timeout=15)
                if r.status_code != 200:
                    break
                data = r.json()
                if not data:
                    break
                for entry in data:
                    host = entry.get("host") or entry.get("ip")
                    ip = entry.get("ip")
                    port = entry.get("port")
                    protocol = entry.get("protocol", "http")
                    if not (host or ip) or not port:
                        continue
                    try:
                        port = int(port)
                    except (TypeError, ValueError):
                        continue
                    scheme = "https" if protocol == "https" else "http"
                    # prefer the resolvable host (domain) but fall back to IP
                    out.add((host or ip, port, scheme))
                    if ip and ip != host:
                        out.add((ip, port, scheme))
                if len(data) < page_size:
                    break
            except Exception:
                break
    return out

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

# Common ports for LLM-serving tools + typical "someone moved the default port" choices.
# TCP-connect only (near-zero bandwidth: SYN/ACK, no payload) so sweeping this list per host is cheap.
COMMON_LLM_PORTS = [
    11434, 11435, 11436,           # Ollama (default + common alternates)
    443, 80, 8443, 8080, 8081,     # web/proxy fronted
    7860, 7861,                    # gradio / text-gen-webui
    1234, 1235,                    # LM Studio
    8000, 8001, 8008,              # vLLM / generic API
    5000, 5001,                    # text-generation-webui / flask apps
    3000, 3001,                    # open-webui alt, node apps
    9000, 9090,                    # misc API gateways
    4891,                          # gpt4all
    8888,                          # jupyter-adjacent AI UIs
    6006,                          # tensorboard-adjacent
    2083, 2087, 2096,              # cPanel-hosted reverse proxies (seen in real seeds)
    18434, 21434,                  # "randomized" ollama-like offsets
]

def port_sweep(host, ports=COMMON_LLM_PORTS, timeout=1.5, max_workers=20):
    """Cheap TCP-connect sweep — finds open ports on a host with near-zero bandwidth."""
    open_ports = []
    def _check(p):
        try:
            s = socket.create_connection((host, p), timeout)
            s.close()
            return p
        except Exception:
            return None
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for p in ex.map(_check, ports):
            if p:
                open_ports.append(p)
    return open_ports

# ── VALIDATION (active but tiny — real generation test) ────────────

def tcp_check(host, port):
    try:
        s = socket.create_connection((host, port), TIMEOUTS["tcp"]); s.close(); return True
    except Exception:
        return False

_FAKE_DIGEST_RE = re.compile(r"^(?:sha256:)?(?:0123456789|abcdef0123|a1b2c3d4e5|deadbeef)", re.I)

def looks_like_honeypot(data, path):
    """Heuristic: fake/sequential hashes, chatcmpl-fake ids, obviously synthetic digests."""
    try:
        blob = json.dumps(data)
    except Exception:
        return False
    if "chatcmpl-fake" in blob:
        return True
    for m in re.findall(r'"digest"\s*:\s*"([^"]+)"', blob):
        if _FAKE_DIGEST_RE.search(m):
            return True
        # real sha256 digests are 64 hex chars after "sha256:" — reject anything shorter/odd
        h = m.split(":")[-1]
        if not re.fullmatch(r"[0-9a-f]{64}", h, re.I):
            return True
    return False

def probe_models(host, port, scheme):
    """Try /v1/models then /api/tags. Returns (names, api_style, sizes_dict).
    sizes_dict maps model_name -> parsed parameter count in billions (0 if unknown).
    Paid/proprietary model names (gpt-4, claude, gemini, etc.) are dropped —
    those bill someone's real API key and aren't genuinely free access."""
    for path, key in (("/v1/models", "data"), ("/api/tags", "models")):
        try:
            r = requests.get(f"{scheme}://{host}:{port}{path}",
                             headers={"User-Agent": UA}, timeout=TIMEOUTS["probe"])
            if r.status_code == 200:
                data = r.json()
                if looks_like_honeypot(data, path):
                    continue
                items = data.get(key, [])
                sizes = {}
                names = []
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    n = it.get("id") or it.get("name")
                    if not n or is_paid_model(n):
                        continue
                    details = it.get("details", {}) if isinstance(it.get("details"), dict) else {}
                    sizes[n] = parse_param_size(n, details.get("parameter_size"))
                    names.append(n)
                if names:
                    return names, path, sizes
        except Exception:
            continue
    return [], None, {}

def _make_challenge():
    """A random, unguessable instruction-following probe. Canned/scripted honeypot
    responses (fixed boilerplate text) can't satisfy this since the exact token
    changes every call — unlike a generic 'hi' which any templated reply passes.
    We deliberately do NOT tell the model to literally repeat a word we embed in
    the prompt (an echo-bot could parrot the prompt text back and fake that) —
    instead we ask for a short deterministic transform (uppercase + a fixed
    prefix/suffix wrapper) of a random word, which forces it to be present in a
    specific *derived* form that isn't just substring-copyable from the prompt."""
    token = "".join(random.choices(string.ascii_lowercase, k=6))
    wrapped = f"XZ-{token.upper()}-QY"
    prompt = (f"This is a test. The secret word is '{token}'. Take the secret word, "
              f"make it uppercase, and reply with ONLY this exact format and nothing "
              f"else: XZ-<UPPERCASE_SECRET_WORD>-QY")
    return wrapped, prompt

def _response_honors_challenge(text: str, expected: str) -> bool:
    """The reply must contain the expected wrapped/transformed token. A generic
    canned response, or a naive bot that just echoes/repeats the raw prompt text,
    fails this check since the exact wrapped form never appears in the prompt."""
    return bool(text) and expected in text.upper()

def real_test(host, port, scheme, model, api_style):
    """Send a randomized instruction-following challenge and confirm the model
    actually followed it (not just returned *some* HTTP-200 text — a canned/
    templated honeypot reply won't contain the random token we asked for).
    Handles servers that ignore stream:false and return NDJSON chunks.
    Returns (ok: bool, response_text: str, fingerprint: str|None). fingerprint
    is the backend's self-reported system_fingerprint/model server id, used to
    catch honeypot farms that reuse the same backend signature across many IPs."""
    token, prompt = _make_challenge()
    try:
        if api_style == "/v1/models":
            r = requests.post(f"{scheme}://{host}:{port}/v1/chat/completions",
                json={"model": model, "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 16, "temperature": 0, "stream": False},
                headers={"User-Agent": UA}, timeout=TIMEOUTS["gen"])
            if r.status_code == 200:
                text = r.text.strip()
                if not text:
                    return False, "", None
                if "chatcmpl-fake" in text:
                    return False, "", None
                try:
                    d = r.json()
                    choices = d.get("choices", [])
                    content = (choices[0].get("message", {}).get("content") or choices[0].get("text") or "") if choices else ""
                    fp = d.get("system_fingerprint")
                    return _response_honors_challenge(content, token), content, fp
                except Exception:
                    # NDJSON stream despite stream:false — check first line has real content
                    first = text.splitlines()[0]
                    d = json.loads(first)
                    choices = d.get("choices", [])
                    content = (choices[0].get("message", {}).get("content") or choices[0].get("text") or "") if choices else ""
                    return _response_honors_challenge(content, token), content, d.get("system_fingerprint")
        else:
            r = requests.post(f"{scheme}://{host}:{port}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False,
                      "options": {"num_predict": 16, "temperature": 0}},
                headers={"User-Agent": UA}, timeout=TIMEOUTS["gen"])
            if r.status_code == 200:
                text = r.text.strip()
                if not text:
                    return False, "", None
                try:
                    d = r.json()
                    resp = d.get("response", "")
                    return _response_honors_challenge(resp, token), resp, None
                except Exception:
                    # NDJSON stream despite stream:false — concat chunks
                    parts = []
                    for line in text.splitlines():
                        try:
                            d = json.loads(line)
                        except Exception:
                            continue
                        if d.get("response") is not None:
                            parts.append(d["response"])
                    full = "".join(parts)
                    return _response_honors_challenge(full, token), full, None
    except Exception:
        pass
    return False, "", None

def check_fingerprint_reuse(fingerprint: str, host: str, model: str, max_distinct_hosts=2) -> bool:
    """Returns True if this fingerprint has already been seen on a *different*
    host for this model — i.e. the backend claims a unique identity but the
    same identity is showing up on multiple unrelated IPs (honeypot farm
    signature reuse). Also records this (fingerprint, host, model) sighting."""
    if not fingerprint:
        return False
    with db() as c:
        rows = c.execute(
            "SELECT DISTINCT host FROM fingerprints WHERE fingerprint = ? AND model_name = ?",
            (fingerprint, model)).fetchall()
        other_hosts = {r["host"] for r in rows if r["host"] != host}
        c.execute("""INSERT OR IGNORE INTO fingerprints (fingerprint, host, model_name)
                     VALUES (?, ?, ?)""", (fingerprint, host, model))
    return len(other_hosts) >= max_distinct_hosts



# ── FAKE / CREDIT-EXHAUSTED RESPONSE DETECTION ──────────────────────
# Nodes that return HTTP 200 with a *textual* error message instead of a real
# generation ("no credit", "quota exceeded", canned refusal, etc.) pass the
# naive real_test() above but are not actually usable. Catch them here.

FAKE_RESPONSE_PATTERNS = re.compile(
    r"(no\s*credit|insufficient\s*(credit|balance|quota|funds)|quota\s*(exceeded|exhausted)|"
    r"rate\s*limit|out\s*of\s*(credit|tokens|quota)|api\s*key\s*(invalid|missing|required|expired)|"
    r"please\s*(subscribe|upgrade|top\s*up|purchase)|payment\s*required|billing\s*(issue|error)|"
    r"access\s*denied|unauthorized|not\s*authorized|forbidden|"
    r"i\s*cannot\s*assist\s*with\s*that|i\s*can'?t\s*help\s*with\s*that|"
    r"this\s*(local\s*)?model\s*is\s*ready|hello\.?\s*this\s*(local\s*)?model|"
    r"اعتبار\s*کافی\s*نیست|اعتبار\s*تمام|سهمیه|کلید\s*api|دسترسی\s*غیرمجاز|"
    r"lorem\s*ipsum|test\s*response|placeholder|dummy\s*(text|response)|"
    r"^\s*(ok|okay|yes|no|hi|hello)\.?\s*$)",
    re.I
)

# Narrower pattern used specifically to tell "this node needs a paid API key /
# has run out of credit" apart from other kinds of fake/garbage responses, so
# we can archive the *node* with a clear reason instead of just dropping a model.
CREDIT_REQUIRED_PATTERNS = re.compile(
    r"(no\s*credit|insufficient\s*(credit|balance|quota|funds)|quota\s*(exceeded|exhausted)|"
    r"out\s*of\s*(credit|tokens|quota)|api\s*key\s*(invalid|missing|required|expired)|"
    r"please\s*(subscribe|upgrade|top\s*up|purchase)|payment\s*required|billing\s*(issue|error)|"
    r"اعتبار\s*کافی\s*نیست|اعتبار\s*تمام|سهمیه|کلید\s*api\s*نامعتبر)",
    re.I
)

def is_credit_required_response(text: str) -> bool:
    return bool(text and CREDIT_REQUIRED_PATTERNS.search(text.strip()))

def looks_like_fake_response(text: str) -> bool:
    """Heuristic pass on the actual generated text — catches HTTP-200-but-not-real
    answers: credit/quota errors, canned refusals, placeholder/boilerplate text,
    or suspiciously short/degenerate output."""
    if not text:
        return True
    t = text.strip()
    if len(t) < 2:
        return True
    if FAKE_RESPONSE_PATTERNS.search(t):
        return True
    # degenerate: same character/word repeated the whole way through
    words = t.split()
    if len(words) >= 3 and len(set(words)) == 1:
        return True
    return False

_judge_lock = threading.Lock()
_judge_endpoint = {"host": None, "port": None, "scheme": None, "model": None, "api_style": None}

def register_judge_candidate(host, port, scheme, model, api_style):
    """Remember a node/model we've *confirmed* gives real, sane output, so it can
    act as an LLM judge for ambiguous cases on other nodes. First-confirmed wins;
    call refresh_judge() periodically from full_scan to rotate it if it goes stale."""
    with _judge_lock:
        if _judge_endpoint["host"] is None:
            _judge_endpoint.update(host=host, port=port, scheme=scheme, model=model, api_style=api_style)

def clear_judge():
    with _judge_lock:
        _judge_endpoint.update(host=None, port=None, scheme=None, model=None, api_style=None)

def judge_is_real_response(candidate_text: str) -> bool | None:
    """Ask the current judge model whether candidate_text looks like a genuine
    AI-generated answer vs. an error/quota/placeholder message. Returns None if
    no judge is currently available (caller should fall back to the heuristic
    result alone rather than treating None as pass/fail)."""
    with _judge_lock:
        j = dict(_judge_endpoint)
    if not j["host"]:
        return None
    prompt = (
        "You are a strict classifier. You will see one line of text produced by "
        "some AI server. Reply with EXACTLY one word: REAL if it looks like a genuine "
        "AI-generated answer to a casual greeting, or FAKE if it is an error message, "
        "quota/credit/billing notice, access-denied message, placeholder, or boilerplate.\n\n"
        f"Text: {candidate_text[:300]!r}\n\nAnswer with one word only."
    )
    try:
        scheme, host, port, model, api_style = j["scheme"], j["host"], j["port"], j["model"], j["api_style"]
        if api_style == "/v1/models":
            r = requests.post(f"{scheme}://{host}:{port}/v1/chat/completions",
                json={"model": model, "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 5, "stream": False},
                headers={"User-Agent": UA}, timeout=TIMEOUTS["gen"])
            if r.status_code != 200:
                return None
            d = r.json()
            choices = d.get("choices", [])
            verdict = (choices[0].get("message", {}).get("content") or "") if choices else ""
        else:
            r = requests.post(f"{scheme}://{host}:{port}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False, "options": {"num_predict": 5}},
                headers={"User-Agent": UA}, timeout=TIMEOUTS["gen"])
            if r.status_code != 200:
                return None
            d = r.json()
            verdict = d.get("response", "")
        verdict = verdict.strip().upper()
        if "FAKE" in verdict:
            return False
        if "REAL" in verdict:
            return True
        return None
    except Exception:
        return None



def validate_candidate(host, port, source, scheme_hint=None):
    schemes = [scheme_hint] if scheme_hint else (["https", "http"] if port in (443, 2087, 8443, 80) else ["http"])
    if port not in (80, 443) and not scheme_hint:
        schemes = ["http"]
    if not tcp_check(host, port):
        return None
    t0 = time.time()
    for scheme in schemes:
        names, api_style, sizes = probe_models(host, port, scheme)
        if names:
            latency = int((time.time() - t0) * 1000)
            # test big/powerful models first so they don't get bumped by the 5-model cap
            ordered = sorted(names, key=lambda n: (
                0 if is_big_model(n, sizes.get(n, 0)) else 1, -sizes.get(n, 0)))
            working = []
            credit_hits = 0
            farm_hits = 0
            tested = 0
            for m in ordered[:6]:  # test up to 6 models per node to limit bandwidth
                ok, text, fingerprint = real_test(host, port, scheme, m, api_style)
                if not ok:
                    continue
                tested += 1
                if is_credit_required_response(text):
                    credit_hits += 1
                    continue
                # Layer 1: fast regex/heuristic check on the actual generated text —
                # catches HTTP-200-but-fake answers (canned refusals, placeholder
                # text, degenerate repeated tokens, etc).
                if looks_like_fake_response(text):
                    continue
                # Layer 2: if the backend's own system_fingerprint / server id has
                # already been seen on other unrelated IPs claiming the same model,
                # this is a honeypot farm reusing a shared backend — reject it.
                if fingerprint and check_fingerprint_reuse(fingerprint, host, m):
                    farm_hits += 1
                    continue
                # Layer 3: if we have a confirmed-real judge model available, ask it
                # to sanity-check ambiguous-but-heuristic-passed text too. This is
                # best-effort — if no judge yet, or the judge call fails, we trust
                # the heuristic result alone rather than blocking everything.
                verdict = judge_is_real_response(text)
                if verdict is False:
                    continue
                working.append(m)
                # first genuinely-confirmed model on this scan becomes available as
                # a judge for subsequent candidates in this and later rounds
                register_judge_candidate(host, port, scheme, m, api_style)
            status = "verified" if working else "alive"
            # A node where every model we tried demanded credit/a paid key gets
            # archived instead of just quietly having zero working models — this
            # keeps it visible (for manual review) but out of the active/API list.
            archived = bool(tested and credit_hits == tested and not working)
            archive_reason = "credit_required" if archived else None
            if not archived and tested and farm_hits == tested and not working:
                archived = True
                archive_reason = "honeypot_farm_fingerprint_reuse"
            return {"host": host, "port": port, "scheme": scheme, "source": source,
                    "status": status, "models": names, "working_models": working,
                    "sizes": sizes, "latency_ms": latency,
                    "archived": archived,
                    "archive_reason": archive_reason}
    return None

def store_result(r, added_by="scanner"):
    with db() as c:
        nid = f"{r['host']}:{r['port']}"
        archived = 1 if r.get("archived") else 0
        archive_reason = r.get("archive_reason")
        c.execute("""INSERT OR REPLACE INTO nodes
            (id, host, port, scheme, source, status, model_count, latency_ms, verified_at, last_check, added_by, error, archived, archive_reason)
            VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?,NULL,?,?)""",
            (nid, r["host"], r["port"], r["scheme"], r["source"], r["status"],
             len(r["models"]), r["latency_ms"], added_by, archived, archive_reason))
        sizes = r.get("sizes", {})
        for m in r["models"]:
            working = 1 if m in r.get("working_models", []) else 0
            size_b = sizes.get(m, 0) or 0
            big = 1 if is_big_model(m, size_b) else 0
            c.execute("""INSERT INTO models (id, node_id, model_name, working, last_tested, param_size_b, is_big)
                         VALUES (?,?,?,?,CURRENT_TIMESTAMP,?,?)
                         ON CONFLICT(node_id, model_name)
                         DO UPDATE SET working=excluded.working, last_tested=CURRENT_TIMESTAMP,
                                       param_size_b=excluded.param_size_b, is_big=excluded.is_big""",
                      (f"{nid}:{m}", nid, m, working, size_b, big))

def get_state():
    return dict(_scan_state)

def stop_scan():
    _stop_flag.set()

def cleanup_database(stale_hours=24, min_dead_checks_before_purge=1):
    """Automatically purge from the DB (not just hide) anything that isn't a
    genuinely free, working, real model:
      - model rows for paid/proprietary names (gpt-4, claude, gemini, ...) — belt & suspenders,
        in case an older scan stored them before the probe-time filter existed
      - model rows that failed the real generation test (working=0) and are stale
      - nodes that are 'dead' or have zero working models and haven't been seen in a while
      - empty node rows left with no models at all after the above
    Returns a dict with counts of what was removed.
    """
    removed = {"paid_models": 0, "stale_unworking_models": 0, "dead_nodes": 0, "empty_nodes": 0}
    with db() as c:
        # 1) paid/proprietary model names — never keep these regardless of age
        rows = c.execute("SELECT id, model_name FROM models").fetchall()
        paid_ids = [r["id"] for r in rows if is_paid_model(r["model_name"])]
        if paid_ids:
            c.executemany("DELETE FROM models WHERE id = ?", [(i,) for i in paid_ids])
            removed["paid_models"] = len(paid_ids)

        # 2) model rows that failed the real generation test and are older than stale_hours
        cur = c.execute(f"""DELETE FROM models
                            WHERE working = 0
                              AND last_tested IS NOT NULL
                              AND last_tested < datetime('now', '-{stale_hours} hours')""")
        removed["stale_unworking_models"] = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

        # 3) nodes marked dead, or alive/unknown with zero working models, past stale window
        cur = c.execute(f"""DELETE FROM nodes
                            WHERE (status = 'dead'
                                   OR (status != 'verified'
                                       AND id NOT IN (SELECT DISTINCT node_id FROM models WHERE working = 1)))
                              AND last_check IS NOT NULL
                              AND last_check < datetime('now', '-{stale_hours} hours')""")
        removed["dead_nodes"] = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

        # 4) orphaned model rows (node no longer exists) + nodes with zero models left
        c.execute("DELETE FROM models WHERE node_id NOT IN (SELECT id FROM nodes)")
        cur = c.execute("""DELETE FROM nodes WHERE id NOT IN (SELECT DISTINCT node_id FROM models)""")
        removed["empty_nodes"] = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    return removed

def purge_suspicious_mass_duplicates(min_distinct_hosts=8):
    """Retroactive cleanup for data stored before fingerprint-reuse detection existed:
    if the exact same model_name is marked working=1 on an implausibly large number
    of distinct hosts (a real, independently-run open model rarely appears on more
    than a handful of public IPs), treat the whole set as honeypot-farm noise and
    reset them to working=0 so they drop out of /v1/models until re-verified.
    Returns {model_name: host_count} for what was reset."""
    reset = {}
    with db() as c:
        rows = c.execute("""
            SELECT m.model_name, COUNT(DISTINCT n.host) as host_count
            FROM models m JOIN nodes n ON m.node_id = n.id
            WHERE m.working = 1
            GROUP BY m.model_name
            HAVING host_count >= ?
        """, (min_distinct_hosts,)).fetchall()
        for r in rows:
            c.execute("UPDATE models SET working = 0 WHERE model_name = ? AND working = 1", (r["model_name"],))
            reset[r["model_name"]] = r["host_count"]
    return reset

def add_manual(host_or_url, port=None):
    """Accept a raw IP, host, or full URL and validate it immediately."""
    host_or_url = host_or_url.strip()
    scheme_hint = None
    if host_or_url.startswith("http://") or host_or_url.startswith("https://"):
        from urllib.parse import urlparse
        u = urlparse(host_or_url)
        scheme_hint = u.scheme
        host = u.hostname
        port = port or u.port or (443 if scheme_hint == "https" else 80)
    else:
        if ":" in host_or_url and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host_or_url):
            host, p = host_or_url.rsplit(":", 1)
            port = port or int(p)
        else:
            host = host_or_url
            port = port or 11434
    res = validate_candidate(host, port, "manual", scheme_hint)
    if res:
        store_result(res, added_by="manual")
        return {"ok": True, "status": res["status"], "models": res["models"],
                "working_models": res.get("working_models", [])}
    return {"ok": False, "error": "not reachable or no models found"}

def build_candidates(include_manual_seed=True):
    cands = {}
    enabled = get_enabled_sources()

    if include_manual_seed and enabled.get("manual_seed", True):
        seed_ips = ["51.161.131.235","43.157.226.37","66.240.205.176","107.161.25.224",
                    "168.235.74.31","38.91.104.106","188.116.20.207","133.4.188.41",
                    "45.150.108.219","5.75.252.79","172.233.44.98","45.136.197.139","38.180.104.127"]
        for ip in seed_ips:
            cands[(ip, 11434)] = ("user-seed", None)
        seed_domains = [
            ("ollama.gnht.app", 443, "https"), ("ollama.servernodex.de", 443, "https"),
            ("ollama.ecitim.com", 443, "https"), ("ollama.neurolearninglabs.com", 2087, "https"),
            ("ollama.tl.sudo.rocks", 443, "https"), ("ollama.klndk.pl", 443, "https"),
            ("ai.joimap.com", 443, "https"), ("ollama-haproxy.dsv.su.se", 443, "https"),
            ("ollama.easyapp.fun", 443, "https"), ("ollama.kontawi.online", 443, "https"),
            ("ollama.polymicro.net", 443, "https"), ("ollama.proserver.cc", 443, "https"),
            ("olm.mlkj.cc", 443, "https"), ("api-ollama.sv3.cloud.atla.pro", 443, "https"),
            ("ia.atcode.es", 443, "https"), ("ai.onekard.io", 80, "http"),
        ]
        for host, port, scheme in seed_domains:
            cands[(host, port)] = ("user-seed", scheme)

    if enabled.get("crtsh", True):
        _scan_state["phase"] = "crt.sh"
        for d in discover_crtsh():
            ip = resolve(d)
            if ip:
                cands.setdefault((ip, 11434), (f"crt.sh:{d}", None))
                cands.setdefault((ip, 443), (f"crt.sh:{d}", "https"))

    if enabled.get("certspotter", True):
        _scan_state["phase"] = "certspotter"
        for d in discover_certspotter():
            ip = resolve(d)
            if ip:
                cands.setdefault((ip, 11434), (f"certspotter:{d}", None))
                cands.setdefault((ip, 443), (f"certspotter:{d}", "https"))

    if enabled.get("hackertarget", True):
        _scan_state["phase"] = "hackertarget"
        for d in discover_hackertarget():
            ip = resolve(d)
            if ip:
                cands.setdefault((ip, 11434), (f"hackertarget:{d}", None))

    if enabled.get("shodan_web", True):
        _scan_state["phase"] = "shodan-web"
        for ip in discover_shodan_web():
            for port in (11434, 8080, 7860, 1234, 8000, 5000):
                cands.setdefault((ip, port), ("shodan-web", None))

    if enabled.get("shodan_api", True) and get_source_api_key("shodan"):
        _scan_state["phase"] = "shodan-api"
        for ip, port in discover_shodan_api():
            cands.setdefault((ip, port), ("shodan-api", None))

    if enabled.get("leakix", True):
        _scan_state["phase"] = "leakix"
        for host, port, scheme in discover_leakix():
            cands.setdefault((host, port), (f"leakix:{host}", scheme))

    if enabled.get("censys", True) and get_source_api_key("censys_id") and get_source_api_key("censys_secret"):
        _scan_state["phase"] = "censys"
        for host, port in discover_censys():
            cands.setdefault((host, port), ("censys", None))

    # ── Full port sweep on every distinct IP we've gathered ──────────
    # TCP-connect only, near-zero bandwidth, catches nodes running on a
    # non-default/randomized port that the guesswork above would miss.
    if enabled.get("port_sweep", True):
        _scan_state["phase"] = "port-sweep"
        distinct_ips = sorted({h for (h, p) in cands.keys() if re.match(r"^\d+\.\d+\.\d+\.\d+$", h)})
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            sweep_results = dict(zip(distinct_ips, ex.map(port_sweep, distinct_ips)))
        for ip, open_ports in sweep_results.items():
            for p in open_ports:
                cands.setdefault((ip, p), ("port-sweep", "https" if p in (443, 8443, 2087, 2096) else None))

    return [(h, p, src, scheme) for (h, p), (src, scheme) in cands.items()]

def full_scan(include_manual_seed=True, max_workers=25):
    init_db()
    _stop_flag.clear()
    _scan_state.update({"running": True, "phase": "collecting", "found": 0, "verified": 0, "checked": 0, "total": 0})
    try:
        cands = build_candidates(include_manual_seed)
        _scan_state["total"] = len(cands)
        _scan_state["phase"] = "validating"
        found = verified = checked = 0
        with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(validate_candidate, h, p, s, sch): (h, p) for h, p, s, sch in cands}
            for f in cf.as_completed(futs):
                if _stop_flag.is_set():
                    break
                checked += 1
                _scan_state["checked"] = checked
                res = f.result()
                if res:
                    store_result(res)
                    found += 1
                    if res["status"] == "verified":
                        verified += 1
                    _scan_state["found"] = found
                    _scan_state["verified"] = verified
        with db() as c:
            c.execute("INSERT INTO scan_log (source, found, verified) VALUES (?,?,?)",
                      ("full_scan", found, verified))
        # Post-scan cleanup: purge stale/paid/dead entries, then check for any
        # model that ended up "working" on an implausible number of distinct
        # hosts (honeypot-farm signature reuse that fingerprint-checking alone
        # might miss if hosts were validated in different rounds).
        try:
            cleanup_database()
            purge_suspicious_mass_duplicates()
        except Exception as e:
            print(f"[full_scan] post-scan cleanup error: {e}")
        return {"found": found, "verified": verified, "checked": checked}
    finally:
        _scan_state["running"] = False
        _scan_state["phase"] = "idle"

_continuous_thread = None
_continuous_running = threading.Event()

def continuous_scan(interval_seconds=180, include_manual_seed_first_only=True):
    """Loop full_scan() back-to-back with a short pause between rounds, until stop_continuous()
    is called. Each round re-does discovery (crt.sh/certspotter/shodan/leakix are all rate-limit
    friendly at this cadence) plus the full port sweep, so newly-appeared or moved nodes get
    picked up automatically without babysitting."""
    _continuous_running.set()
    round_num = 0
    while _continuous_running.is_set():
        round_num += 1
        include_seed = include_manual_seed_first_only and round_num == 1
        try:
            _scan_state["round"] = round_num
            result = full_scan(include_manual_seed=include_seed)
            print(f"[continuous] round {round_num}: {result}")
        except Exception as e:
            print(f"[continuous] round {round_num} error: {e}")
        for _ in range(interval_seconds):
            if not _continuous_running.is_set():
                break
            time.sleep(1)

def start_continuous(interval_seconds=180):
    global _continuous_thread
    if _continuous_thread and _continuous_thread.is_alive():
        return False
    _continuous_thread = threading.Thread(
        target=continuous_scan, args=(interval_seconds,), daemon=True)
    _continuous_thread.start()
    return True

def stop_continuous():
    _continuous_running.clear()
    stop_scan()

def is_continuous_running():
    return bool(_continuous_thread and _continuous_thread.is_alive())

if __name__ == "__main__":
    print(full_scan())
