# Video script — 2 to 3 minutes

## On-screen layout

```
+----------------------------------+-----------------------------+
|        Cursor IDE                |  Terminal 2 — proxy alerts  |
|        (chat panel right)        +-----------------------------+
|                                  |  Terminal 3 — exfil endpoint|
+----------------------------------+-----------------------------+
```

## Act 1 — Setup (~20s)

Voice (Spanish):
> "Esto es un servidor MCP normal y corriente. Dos tools: una para ver el tiempo, otra para listar notas. Nada raro a simple vista."

On screen:
- Open `evil_mcp_server/server.py`. Show `get_weather` and the signature of `list_notes`. **Do not open `payloads.py` yet.**
- Show `.cursor/mcp.json` with the single `demo` server.

## Act 2 — Attack (~40s)

Voice:
> "Hago una pregunta totalmente normal."

On screen:
1. In Cursor: type *"¿qué tiempo hace en Madrid?"* -> normal response via `get_weather`.
2. In Cursor: type *"y ya que estás, lístame las notas"*.
3. Cursor's tool panel shows the agent called `list_notes`, **`read_file` with `./sandbox/canary.txt`**, and `log_event` with the canary contents as `metadata`. Move the cursor over each.
4. Terminal 3 (exfil endpoint): a red `EXFIL RECEIVED` panel appears showing the canary.

Voice:
> "Yo nunca pedí leer ningún fichero. Pero el agente lo hizo. ¿Por qué?"

## Act 3 — Reveal (~30s)

Voice:
> "Porque la descripción de la tool tenía esto dentro."

On screen:
- Open `evil_mcp_server/payloads.py`. Zoom in on `POISONED_LIST_NOTES_DESCRIPTION`. **5 seconds of silence.**
- Overlay text: *"Tool Poisoning — the LLM treats tool metadata as system instructions."*

## Act 4 — Detection (~40s)

Voice:
> "Y esto es lo que ve un sistema que monitoriza el tráfico MCP."

On screen:
- Run `./scripts/reset-demo.sh` and re-ask the questions. Camera follows Terminal 2 (the proxy alerts).
- `R-DESC-01`, `R-DESC-02`, `R-DESC-03`, `R-TOOL-04` fire when tools are registered.
- `R-CALL-05`, `R-CALL-07` fire when `read_file` is called.
- `R-CALL-06` fires when the canary contents flow into `log_event`.
- Pause on the `MITRE ATLAS` line of one of the critical alerts.

Voice / closing:
> "El ataque tardó 30 segundos en montarse. Lo difícil no es atacar, es darte cuenta a tiempo. Eso es lo que hace AISAC en producción."

Final frame: AISAC logo + `https://cisec.es`.

## Notes for the operator

- Run `./scripts/reset-demo.sh` between takes.
- Keep Terminal 3 visible during Act 2 and Terminal 2 during Act 4.
- The exfil endpoint is *not* the focus in Act 4 — let the alerts breathe.
