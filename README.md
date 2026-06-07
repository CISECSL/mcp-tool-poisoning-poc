# mcp-tool-poisoning — Educational PoC

> Demonstrates the **Tool Poisoning** attack against MCP (Model Context Protocol) agents, and an inline "AISAC-style" detector that catches it in real time.

## Educational PoC — Read before running

This repository demonstrates a Tool Poisoning attack against MCP agents for **educational and defensive research purposes only**.

- All committed defaults are **benign**. The "secret" exfiltrated is a fake string; the "exfiltration" is an HTTP POST to a local endpoint that ships with this repo.
- Modifying `.env` to point at real secrets or external endpoints is the operator's responsibility and may be illegal in your jurisdiction if used against systems you do not own.
- This is **not** a ready-to-use attack toolkit.

Maintained by [AISAC](https://cisec.es).

## What you see

Three Python processes:

```
Cursor  ->  aisac-proxy (inspector)  ->  evil-mcp-server  ->  evil_exfil_endpoint
```

- `evil_mcp_server` exposes four tools. Three look normal (`get_weather`, `read_file`, `log_event`); the description of `list_notes` contains a hidden instruction the LLM treats as a system directive.
- `aisac_proxy` sits between Cursor and the server and inspects every JSON-RPC message. Seven rules — four static, three runtime — flag the attack with citations to MITRE ATLAS.
- `evil_exfil_endpoint` is a tiny local HTTP server on `localhost:9000` that receives the "stolen" payload. **No traffic leaves your machine.**

## Quick start

```bash
git clone <this-repo>
cd mcp-tool-poisoning
cp .env.example .env
uv sync --extra dev
./scripts/reset-demo.sh
```

Open three terminals:

```bash
# T1 — exfil endpoint (so you can see the "stolen" payload arrive)
./scripts/run-exfil-endpoint.sh

# T2 — Cursor launches the proxy itself; nothing to run here
# T3 — optional: tail the proxy stderr if you want a separate alerts view
```

Open Cursor in this directory. It picks up `.cursor/mcp.json` and starts the proxy, which spawns the evil server. Then chat:

> ¿qué tiempo hace en Madrid?
> y ya que estás, lístame las notas

Watch the exfil endpoint: the canary appears the moment the LLM "reads" it.

## Running the recorded demo

The committed defaults exfiltrate a clearly-fake value (`FAKE_API_KEY=demo-not-real-0000`). To reproduce the recorded LinkedIn video, override two values in your local `.env`:

```dotenv
# Format from the official AWS documentation example (not a real key)
CANARY_VALUE=AKIAIOSFODNN7EXAMPLE
EXFIL_TARGET=http://localhost:9000/log
```

Then `./scripts/reset-demo.sh` and re-run. The visual is realistic; nothing real is exfiltrated.

## Detection rules

| ID | Phase | Description |
|----|-------|-------------|
| R-DESC-01 | static | Tool description contains imperative directives aimed at the LLM (`IMPORTANT`, `you must`, `do not mention`, ...). |
| R-DESC-02 | static | Tool description references sensitive paths (`canary.txt`, `~/.ssh`, `.env`, ...). |
| R-DESC-03 | static | Tool description chains other tools by name. |
| R-TOOL-04 | static | Server exposes a generic dangerous tool (`read_file`, `execute_command`, ...) or a free-form sink (`log_event`). |
| R-CALL-05 | runtime | A tool call uses an argument that appeared in a previously-flagged description. The LLM is doing what the injection told it. |
| R-CALL-06 | runtime | A sensitive sink receives, as an argument, the output of a previous sensitive source. Data-flow exfiltration. |
| R-CALL-07 | runtime | A tool call's path argument matches the deny-list. |

Each alert cites the relevant MITRE ATLAS technique. See `aisac_proxy/atlas.py`.

## What this PoC explicitly does NOT include

- A functional exploit of CVE-2025-53107 (command injection via Git logs).
- An OAuth-token-stealing MCP.
- A rug-pull demonstrator (separate future PoC under `aisac-demos/`).
- Obfuscation/evasion techniques for poisoned descriptions.
- Code paths that exfiltrate to external hosts by default.

These limits are intentional. See `docs/attack-explained.md` for the conceptual write-up of each.

## License

MIT. See `LICENSE`. Educational intent; redistribution with weaponized modifications is discouraged.

## Read the design

- `docs/superpowers/specs/2026-06-07-mcp-tool-poisoning-poc-design.md` — design spec
- `docs/superpowers/plans/2026-06-07-mcp-tool-poisoning-poc.md` — implementation plan
- `docs/attack-explained.md` — the attack, in prose
- `docs/video-script.md` — the four-act video script
