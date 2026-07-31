# OpenCompute

Self-hosted, OpenAI-compatible API that aggregates publicly-exposed Ollama-compatible
inference nodes discovered on the internet. It continuously scans for open nodes,
**actively verifies** every model actually generates real text (not a honeypot or a
paid-key wall), and serves the working ones behind a single `/v1/chat/completions`
endpoint you can point any OpenAI client at.

⚠️ **Disclaimer:** this project only *discovers and tests* endpoints that are already
publicly reachable on the internet without authentication. It does not exploit,
bypass auth, or access anything private. Use responsibly and at your own risk —
whether querying an exposed node is appropriate depends on your jurisdiction and
the target's terms of service.

## Features

- **Multi-source discovery** — crt.sh, CertSpotter, HackerTarget, Shodan (free web
  search + optional paid API), LeakIX, Censys, and a lightweight TCP port-sweep.
  All free-tier sources work with zero configuration; Shodan/LeakIX/Censys can be
  upgraded with your own API key from the Settings tab for deeper coverage.
- **Real validation, not just a port check** — every candidate node gets an actual
  generation request sent to it. Responses are run through multiple honeypot/fake
  filters:
  - regex/heuristic detection of canned refusals, credit-exhausted messages, and
    placeholder text
  - LLM-judge cross-check using an already-confirmed-real model
  - backend fingerprint reuse detection (catches "honeypot farms" that clone the
    same fake backend across hundreds of IPs)
- **Auto-archiving** — nodes where every model demands a paid API key or credits
  are automatically archived (kept visible for review, excluded from the live API)
  instead of silently dropped.
- **Big-model prioritization** — models ≥32B params or from known strong families
  (DeepSeek, Qwen, Llama 70B+, GLM, Mixtral, Command R+, ...) are tested first and
  ranked higher in `/v1/models`.
- **Continuous background scanning** — runs indefinitely on a configurable interval
  until you stop it, re-validating known nodes and discovering new ones.
- **OpenAI-compatible API** — `/v1/models` and `/v1/chat/completions`, drop-in for
  any OpenAI SDK/client. Bearer-token protected, key configurable from Settings.
- **Web dashboard** — dark-themed control panel (Dashboard / Models / Nodes /
  Settings tabs), English by default with a Persian toggle, live source-distribution
  chart, sortable/filterable tables, per-source API key management with built-in
  key testing before it's saved.

## Quick start

```bash
git clone https://github.com/HACK3RRABBIT/opencompute.git
cd opencompute
pip install -r requirements.txt
python3 server.py
```

Dashboard: http://localhost:5555
Default API key: `sk-1234` (change it from the Settings tab, or via the
`OPENCOMPUTE_API_KEY` env var before first run)

## Using the API

```bash
curl http://localhost:5555/v1/models -H "Authorization: Bearer sk-1234"

curl -X POST http://localhost:5555/v1/chat/completions \
  -H "Authorization: Bearer sk-1234" \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3.1:8b", "messages": [{"role": "user", "content": "Hello!"}]}'
```

Or with any OpenAI SDK:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:5555/v1", api_key="sk-1234")
resp = client.chat.completions.create(model="llama3.1:8b", messages=[{"role": "user", "content": "Hi"}])
```

## Discovery sources

| Source | Needs API key? | Notes |
|---|---|---|
| crt.sh | No | Certificate transparency logs |
| CertSpotter | No | Certificate transparency logs |
| HackerTarget | No | Subdomain enumeration |
| Shodan (web search) | No | Free HTML scrape of public search |
| Shodan (API) | Yes | Richer results, consumes query credits |
| LeakIX | Yes (free) | Sign up at leakix.net |
| Censys | Yes (free tier) | API ID + Secret from search.censys.io |
| Port sweep | No | TCP-connect only, near-zero bandwidth |

Configure API keys from the **Settings** tab — each key is tested with a real,
cheap API call before being saved, and every source can be toggled on/off
independently.

## Architecture

```
scanner.py   discovery (crt.sh/CertSpotter/HackerTarget/Shodan/LeakIX/Censys/port-sweep)
             + real validation (generation test, honeypot/fake-response filtering,
               fingerprint-reuse detection, credit-required auto-archiving)
server.py    FastAPI app — OpenAI-compatible /v1 API + control API + dashboard
webui.html   dark-themed dashboard (Dashboard/Models/Nodes/Settings), EN/FA
opencompute.db   SQLite (nodes, models, settings, fingerprints) — gitignored
```

## Notes

- The bundled `opencompute.db` is *not* committed — each deployment builds its own
  from scratch by running a scan.
- No credentials are hardcoded anywhere in this repo; everything (main API key,
  per-source scanner keys) is configured at runtime via the Settings tab or
  environment variables and stored in the local SQLite database.
