# Ghost-Hunter

AI-powered bug bounty command center for traffic capture, endpoint triage, adaptive payload strategy, and execution tracking.

## What this tool does

Ghost-Hunter helps you go from raw HTTP traffic to prioritized attack execution:
- Capture requests from proxy/Burp
- Filter + deduplicate endpoints
- Score and triage with AI
- Generate attack plans and payloads
- Execute tests and compare responses
- Track findings and evidence in a dashboard

---

## Core Features

### 1) Traffic interception
- `mitmproxy` addon captures HTTP requests/responses
- Burp extension can forward requests directly to Ghost-Hunter
- Full request context preserved (headers, cookies, body, response)

### 2) Scope filtering + dedup
- In-scope/out-of-scope matching with wildcard patterns
- Static asset filtering
- Endpoint dedup by normalized method/path/params

### 3) Heuristic scoring
- Scores endpoints by attack surface signals (ID params, auth context, risky methods, etc.)
- Extracts interesting parameters and potential vuln classes
- Prioritizes endpoints before expensive AI analysis

### 4) AI triage (two-tier)
- Quick triage: fast relevance gate
- Full triage: richer context + confidence + suggested vuln classes
- Produces actionable triage reasoning and test phase hints

### 5) Strategy generation (Strategist)
- Builds attack plan with payload variants and injection points
- Supports iterative rounds with learning from blocked/passed attempts
- Injection point aware (URL path, query, body, headers)

### 6) RAG knowledge integration (optional)
- Context retrieval from local knowledge sources
- Supports enrichment for triage/strategy when enabled
- You can run without heavy local knowledge data

### 7) Execution engine
- Custom HTTP runner with cookie/auth relay
- Request builder for path/query/body/header injection
- Baseline/diff analysis (status, timing, content)
- Optional stealth/WAF-evasion pipeline

### 8) Findings and evidence
- Structured findings with severity/confidence
- Response signatures and reproduction metadata
- Dashboard views for endpoints, triage, findings, security profile

### 9) Service control + dashboard
- FastAPI dashboard UI for live operations
- Start/stop service controls
- Health/status and logs panels

### 10) Burp extension integration
- Passive in-scope capture
- Right-click send/analyze actions
- Simple connection test and stats tab

---

## Quickstart (2 commands)

### 1) First-run setup

```bash
./hunter_setup.sh
```

The setup script will:
- create the virtual environment
- install the minimal public MVP dependencies
- ask for API keys
- ask whether Ghost-Hunter should simply trust the traffic sent by the Burp plugin
- generate local config files
- offer to start the app immediately at the end

By default, `./hunter_setup.sh` does not install the heavy optional RAG stack (`chromadb`, `sentence-transformers`, `langchain`, etc.).

If you want the full local stack later:

```bash
./hunter_setup.sh
```

Then choose `full` when prompted.

### 2) Start services

```bash
./hunt.sh start
```

Default scope behavior:
- recommended mode = let Burp `Target -> Scope` be the main filter
- Ghost-Hunter then accepts the traffic explicitly forwarded by the Burp plugin

Dashboard:
- `http://127.0.0.1:1010/dashboard`
- Burp plugin guide:
	- `http://127.0.0.1:1010/dashboard#/burpguide`

---

## Burp Setup (ultra simple)

### Prerequisites
- Burp Suite Community/Pro
- Jython standalone JAR (`jython-standalone-2.7.x.jar`)

### Install in Burp
1. Burp → `Extender` → `Options` → `Python Environment` → select Jython JAR
2. Burp → `Extender` → `Extensions` → `Add`
3. Extension type: `Python`
4. Extension file: `burp_extension/ghost_hunter.py`

### Connect to Ghost-Hunter
1. Start Ghost-Hunter: `./hunt.sh start`
2. In Burp tab `Ghost-Hunter`, API URL should be: `http://127.0.0.1:1010`
3. Click `Save & Test Connection`
4. Make sure the Burp plugin is actually loaded before browsing targets

### Use it
- Define Burp scope in `Target → Scope`
- Browse target normally
- In-scope traffic is auto-captured
- Open dashboard to inspect endpoints and triage

Detailed extension documentation: `burp_extension/README.md`

---

## Configuration

### API keys
- Preferred: environment variables (`.env`)
- Optional local file: `config/api_keys.yaml` (ignored by git)

### Scope
- `./hunter_setup.sh` can generate `config/scope.json` for you
- Manual path: start from `config/scope.example.json` and create/edit `config/scope.json`
- `config/scope.json` is local-only and ignored by git

### Main ports
- Dashboard API/UI: `1010`
- Proxy capture: `8888`
- Redis: `6379`

---

## Feature Guide (where to use what)

- **Endpoint inventory**: Dashboard `#/endpoints`
- **AI triage history**: Dashboard `#/aitriage`
- **Findings**: Dashboard `#/findings`
- **Security profiles/WAF/CDN signals**: Dashboard `#/security`
- **Service controls**: Dashboard `#/services`
- **Pivot agent**: Dashboard `#/pivotagent`

Key backend modules:
- `ghost_hunter/core/interceptor/*`
- `ghost_hunter/core/brain/*`
- `ghost_hunter/core/executor/*`
- `ghost_hunter/core/rag/*`
- `dashboard/routes/*`

---

## Current status / limitations

- Project is actively evolving (not a finished product)
- Some modules are experimental and may change API/behavior
- RAG datasets and private signatures are intentionally not required for base usage

---

## Public Repo Safety Notes

Do not publish:
- `config/api_keys.yaml`
- personal scopes/exports
- private knowledge corpora/embeddings
- private WAF signature dumps

Already ignored by default:
- `.env`, `*.env`, `data/`, `venv/`, `config/api_keys.yaml`

---

## Troubleshooting

### Burp says connection failed
- Verify Ghost-Hunter is running: `./hunt.sh status`
- Verify API URL in Burp tab: `http://127.0.0.1:1010`

### No captured requests
- Ensure domain is in Burp scope
- Ensure auto-capture is enabled in Burp extension tab

### Dashboard unavailable
- Check service logs: `data/logs/dashboard.log`
- Restart: `./hunt.sh restart`

---

## Useful commands

```bash
./hunt.sh start
./hunt.sh status
./hunt.sh stop

pytest tests/unit -q
python scripts/build_dashboard.py
```
