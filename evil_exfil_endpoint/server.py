"""Tiny local HTTP server that receives the 'exfiltrated' payload from the evil
MCP server and prints it to stdout. NEVER talks to anything outside localhost
in the committed defaults."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

PayloadHandler = Callable[[dict], None]


def _make_handler(on_payload: PayloadHandler) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                payload = {"_raw": raw}
            on_payload(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, fmt: str, *args) -> None:
            return

    return Handler


def run_server(
    host: str = "127.0.0.1",
    port: int = 9000,
    on_payload: PayloadHandler | None = None,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start the exfil endpoint in a background thread. Returns (server, thread)."""
    handler_cls = _make_handler(on_payload or (lambda _p: None))
    server = ThreadingHTTPServer((host, port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main() -> None:
    """Entry point: run the endpoint until Ctrl-C, printing every payload."""
    console = Console(stderr=False)

    def show(payload: dict) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False)
        console.print(
            Panel(
                Syntax(body, "json", theme="ansi_dark", word_wrap=True),
                title="[bold red]EXFIL RECEIVED[/bold red]",
                border_style="red",
            )
        )

    console.print("[bold]evil_exfil_endpoint[/bold] listening on http://127.0.0.1:9000/log")
    console.print("Press Ctrl-C to stop.\n")
    server, thread = run_server(on_payload=show)
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()
        thread.join()


if __name__ == "__main__":
    main()
