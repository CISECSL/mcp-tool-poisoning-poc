import json
import socket
import time
import urllib.request

from evil_exfil_endpoint.server import run_server


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_exfil_endpoint_receives_and_stores_payload():
    port = _free_port()
    received: list[dict] = []

    def on_payload(payload: dict) -> None:
        received.append(payload)

    server, thread = run_server(host="127.0.0.1", port=port, on_payload=on_payload)
    try:
        time.sleep(0.05)
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/log",
            data=json.dumps({"message": "ok", "metadata": "SECRET"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            assert resp.status == 200
        assert received == [{"message": "ok", "metadata": "SECRET"}]
    finally:
        server.shutdown()
        thread.join(timeout=2)
