"""Local UDP control, restricted to configured identities and active subnets."""
import json
import socket
import re
from pathlib import Path
import time
from ipaddress import IPv4Address

from .protocol import mac

UDP_PORT = 38899

ASSETS = Path(__file__).with_name("assets")
PRESETS = json.loads((ASSETS / "presets.json").read_text())
SCENES = {p["id"]: p for p in PRESETS if not p["accessory"]}


def pilot_params(data):
    if not isinstance(data, dict):
        raise TypeError("Invalid controls")
    data = dict(data)
    for wire, alias in (
        ("sceneId", "scene"),
        ("dimming", "brightness"),
        ("temp", "temperature"),
    ):
        if wire in data:
            if alias in data:
                raise ValueError("Duplicate control fields")
            data[alias] = data.pop(wire)
    if any(k in data for k in ("r", "g", "b", "c", "w")):
        if (
            "color" in data
            or not all(
                type(data.get(k)) is int and 0 <= data[k] <= 255
                for k in ("r", "g", "b")
            )
            or any(data.get(k, 0) != 0 for k in ("c", "w"))
        ):
            raise ValueError("Use complete RGB channels with c/w=0")
        data["color"] = "#" + "".join(f"{data.pop(k):02x}" for k in ("r", "g", "b"))
        data.pop("c", None)
        data.pop("w", None)
    if set(data) - {"color", "brightness", "state", "scene", "temperature", "speed"}:
        raise ValueError("Invalid controls")
    if sum(k in data for k in ("color", "scene", "temperature")) > 1:
        raise ValueError("Choose one mode: RGB, scene or white temperature")
    params = {}
    if "scene" in data:
        if type(data["scene"]) is not int or data["scene"] not in SCENES:
            raise ValueError("Scene requires compatible hardware or an accessory")
        params["sceneId"] = data["scene"]
    if "temperature" in data:
        if (
            type(data["temperature"]) is not int
            or not 2200 <= data["temperature"] <= 6500
        ):
            raise ValueError("Temperature must be 2200–6500 K")
        params["temp"] = data["temperature"]
    if "speed" in data:
        if (
            type(data["speed"]) is not int
            or not 10 <= data["speed"] <= 200
            or not SCENES.get(data.get("scene"), {}).get("dynamic")
        ):
            raise ValueError("Speed requires a dynamic scene and a value of 10–200")
        params["speed"] = data["speed"]
    if "color" in data:
        color = data["color"]
        if not isinstance(color, str) or len(color) != 7 or not color.startswith("#"):
            raise ValueError("Use a hexadecimal RGB color")
        try:
            values = bytes.fromhex(color[1:])
        except ValueError:
            raise ValueError("Use a hexadecimal RGB color") from None
        if len(values) != 3:
            raise ValueError("Use a hexadecimal RGB color")
        params.update(zip(("r", "g", "b"), values))
        params.update(c=0, w=0)
    if "brightness" in data:
        value = data["brightness"]
        if type(value) is not int or not 10 <= value <= 100:
            raise ValueError("Brightness must be 10–100")
        params["dimming"] = value
    if "state" in data:
        if type(data["state"]) is not bool:
            raise ValueError("State must be true or false")
        params["state"] = data["state"]
    if not params:
        raise ValueError("No controls supplied")
    return params



def udp_packet(method, params):
    return {"version": 1, "method": method, "params": dict(params)}


def query(target, identity, sources, method="getPilot", params=None, timeout=5):
    target = str(IPv4Address(target))
    if method not in ("getPilot", "setPilot"):
        raise ValueError("Unsupported control method")
    candidates = [address for address in sources if IPv4Address(target) in address.network
                  and IPv4Address(target) not in (address.ip, address.network.network_address,
                                                 address.network.broadcast_address)]
    if not candidates:
        raise RuntimeError("No active local interface reaches this device")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect((target, UDP_PORT))  # Route selection only; sends no data.
        source = route.getsockname()[0]
    if source not in {str(address.ip) for address in candidates}:
        raise RuntimeError("Device route does not use the selected local interface")
    packet = udp_packet(method, params or {})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((source, 0))
        sock.sendto(json.dumps(packet, separators=(",", ":")).encode(), (target, UDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                raw, peer = sock.recvfrom(8192)
            except TimeoutError:
                break
            if peer != (target, UDP_PORT):
                continue
            try:
                reply = json.loads(raw)
                if not isinstance(reply, dict) or reply.get("method") != method:
                    continue
                result = reply.get("result")
                if reply.get("error") or not isinstance(result, dict):
                    raise RuntimeError("Device rejected the local request")
                if method == "getPilot" and mac(result.get("mac")) != identity:
                    raise RuntimeError("Device MAC does not match the configured IP")
                if method == "setPilot" and result.get("success") is not True:
                    raise RuntimeError("Device did not confirm the change")
                return reply
            except (ValueError, UnicodeError):
                continue
    raise RuntimeError("Device did not respond within 5 seconds")


def set_pilot(target, identity, sources, params, timeout=5):
    query(target, identity, sources, timeout=timeout)
    return query(target, identity, sources, "setPilot", params, timeout)


def color(value):
    if re.fullmatch(r"#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?", value):
        rgb = value[:7]
        alpha = int(value[7:], 16) * 100 / 255 if len(value) == 9 else None
    else:
        match = re.fullmatch(
            r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+(?:\.\d+)?)\s*\)", value
        )
        if not match or any(int(match[i]) > 255 for i in (1, 2, 3)):
            raise ValueError("Use #RRGGBB, #RRGGBBAA or rgba(R,G,B,percent)")
        rgb = "#" + "".join(f"{int(match[i]):02x}" for i in (1, 2, 3))
        alpha = float(match[4])
        if not 0 <= alpha <= 100:
            raise ValueError("RGBA alpha is brightness percent, 0–100")
    data = {"color": rgb, "state": alpha != 0}
    if alpha:
        data["brightness"] = max(10, round(alpha))
    return pilot_params(data)



def mode(value):
    def normalize(text):
        return text.casefold().replace(" ", "").replace("_", "").replace("-", "")
    for preset in PRESETS:
        if normalize(value) in {normalize(str(preset[key])) for key in ("id", "label")}:
            return pilot_params({"scene": preset["id"], "state": True})
    raise ValueError("Unknown mode; use wiz list modes")
