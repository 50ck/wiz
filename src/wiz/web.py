"""Local HTTP panel, adapted from wizbind; no AP/DHCP services."""
import json
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .config import read_devices
from .control import ASSETS, PRESETS, SCENES, pilot_params, query, set_pilot, udp_packet
from .system import Commands, inventory, usable


def serve(interface=None, port=24800, *, host="0.0.0.0", stop_event=None, open_browser=True):
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid web port")
    devices = read_devices()
    sources = tuple(address for link, address in usable(inventory(Commands()))
                    if interface is None or link.name == interface)
    peers = list(devices)
    page = (ASSETS / "index.html").read_bytes()

    def selected(values):
        if not isinstance(values, list) or not values or len(values) > 32:
            raise ValueError("Select 1–32 devices")
        if any(not isinstance(ip, str) or ip not in devices for ip in values):
            raise ValueError("Select configured devices only")
        return list(dict.fromkeys(values))

    def exchange(target, params=None):
        data = {"ip": target, "request": udp_packet("getPilot" if params is None else "setPilot", params or {})}
        try:
            identity = devices[target]["mac"]
            data["response"] = (query(target, identity, sources, timeout=5) if params is None
                                else set_pilot(target, identity, sources, params, timeout=5))
            if params is not None and "sceneId" in params:
                deadline = time.monotonic() + 2
                while True:
                    data["readback"] = query(target, identity, sources, timeout=5)
                    if data["readback"]["result"].get("sceneId") == params["sceneId"]:
                        break
                    if time.monotonic() >= deadline:
                        data["error"] = "The device did not confirm this preset"
                        return 422, data
                    time.sleep(0.1)
            return 200, data
        except (OSError, RuntimeError, ValueError, TypeError):
            data["error"] = "Device offline or change not confirmed"
            return 502, data

    def group(targets, params=None):
        with ThreadPoolExecutor(max_workers=min(32, len(targets))) as pool:
            results = list(pool.map(lambda ip: exchange(ip, params), targets))
        return {"results": [dict(data, ok=code == 200) for code, data in results]}

    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

        def reply(self, code, value, content_type="application/json; charset=utf-8"):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self.reply(200, page, "text/html; charset=utf-8")
            if self.path.startswith("/assets/"):
                name = self.path.removeprefix("/assets/")
                if name == Path(name).name and name.endswith((".svg", ".json")) and (ASSETS / name).is_file():
                    return self.reply(200, (ASSETS / name).read_bytes(),
                                      "image/svg+xml" if name.endswith(".svg") else "application/json")
                return self.reply(404, {"error": "Unknown asset"})
            path = urlsplit(self.path)
            if path.path == "/devices":
                return self.reply(200, {"devices": peers, "labels": {ip: item["label"] for ip, item in devices.items()}})
            if path.path != "/state":
                return self.reply(404, {"error": "Unknown endpoint"})
            try:
                arguments = parse_qs(path.query)
                if "ip" in arguments:
                    return self.reply(200, group(selected(arguments["ip"])))
                if not peers:
                    return self.reply(200, {"results": []})
                code, data = exchange(peers[0])
                return self.reply(code, data)
            except (ValueError, TypeError) as error:
                return self.reply(400, {"error": str(error)})

        def do_POST(self):
            if self.headers.get("Origin") != "http://" + self.headers.get("Host", ""):
                return self.reply(403, {"error": "Same-origin requests only"})
            if self.path != "/pilot":
                return self.reply(404, {"error": "Unknown endpoint"})
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 1 <= size <= 1024 or self.headers.get_content_type() != "application/json":
                    raise ValueError("Send a small JSON object")
                controls = json.loads(self.rfile.read(size))
                if not isinstance(controls, dict):
                    raise TypeError("Send a JSON object")
                targets = selected(controls.pop("targets")) if "targets" in controls else None
                params = pilot_params(controls)
            except (ValueError, TypeError, UnicodeError) as error:
                return self.reply(400, {"error": "Invalid JSON" if isinstance(error, json.JSONDecodeError) else str(error)})
            if targets is not None:
                return self.reply(200, group(targets, params))
            if not peers:
                return self.reply(400, {"error": "Select a configured device"})
            code, data = exchange(peers[0], params)
            self.reply(code, data)

    with ThreadingHTTPServer((host, port), Handler) as server:
        if stop_event is not None:
            def stop():
                stop_event.wait()
                server.shutdown()
            threading.Thread(target=stop, daemon=True).start()
        url = f"http://127.0.0.1:{port}/"
        print(f"Listening on {host}:{port}\n{url}", flush=True)
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        finally:
            print("Shutting down web server...", flush=True)
            if stop_event is not None:
                stop_event.set()

