"""Source-bound HTTP setup and bounded discovery, without root sockets."""
import http.client
import json
import re
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address

from .system import gateway, inventory, neighbors, usable
from .config import save_device


class SetupUnavailable(RuntimeError):
    """The setup endpoint could not be reached or closed the connection."""


class SetupRejected(RuntimeError):
    """A reachable setup endpoint returned an error or invalid response."""


def mac(value):
    value = re.sub(r"[:-]", "", value).lower() if isinstance(value, str) else ""
    if not re.fullmatch(r"[0-9a-f]{12}", value) or int(value, 16) == 0 or int(value[:2], 16) & 1:
        raise ValueError("Invalid device MAC")
    return value


def identify(data):
    if (not isinstance(data, dict) or not isinstance(data.get("name"), str)
            or not data["name"] or not isinstance(data.get("fw"), str)
            or type(data.get("status")) is not int):
        raise ValueError("Invalid WiZ device response")
    return mac(data.get("mac"))


def request(address, peer, path, payload=None, timeout=2):
    target = IPv4Address(peer)
    if path not in ("/device", "/pairing", "/complete") or target not in address.network or target in (
            address.ip, address.network.network_address, address.network.broadcast_address):
        raise ValueError("Setup endpoint must be on the selected local network")
    connection = http.client.HTTPConnection(str(target), timeout=timeout,
                                             source_address=(str(address.ip), 0))
    try:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        connection.request("GET" if path == "/device" else "POST", path, body,
                           {"Content-Type": "application/json; charset=utf-8", "Connection": "close"})
        reply = connection.getresponse()
        if reply.status != 200:
            raise SetupRejected(f"Device rejected {path}: HTTP {reply.status}")
        raw = reply.read(8193)
        if len(raw) > 8192:
            raise SetupRejected("Device returned an oversized setup response")
        try:
            data = json.loads(raw) if raw.strip() else {}
        except (ValueError, UnicodeError):
            raise SetupRejected("Device returned invalid setup JSON") from None
        if not isinstance(data, dict):
            raise SetupRejected("Device returned an invalid setup response")
        result = data.get("result")
        if (data.get("error") or data.get("success") is False
                or isinstance(result, dict) and result.get("success") is False):
            raise SetupRejected(f"Device returned an error for {path}")
        return data
    except (OSError, http.client.RemoteDisconnected):
        raise SetupUnavailable("Device HTTP exchange failed") from None
    except http.client.HTTPException:
        raise SetupRejected("Device returned an invalid HTTP response") from None
    finally:
        connection.close()


def wait_for_setup_exit(address, peer, identity, timeout=45):
    """Poll before host disconnect; HTTP errors never count as an AP transition."""
    print("Waiting for the device to close its WiZConfig connection...", flush=True)
    deadline = time.monotonic() + timeout
    failures, status = 0, None
    while time.monotonic() < deadline:
        try:
            device = request(address, peer, "/device", timeout=min(2, max(0.01, deadline - time.monotonic())))
        except SetupUnavailable:
            failures += 1
            if failures >= 3:
                print("WiZConfig is no longer reachable.", flush=True)
                return
        else:
            failures = 0
            if identify(device) != identity:
                raise SetupRejected("Device identity changed after /pairing")
            status = device["status"]
            if status in (4, 6, 8):
                raise SetupRejected(f"Device reported pairing failure: status={status}")
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"WiZConfig remained reachable after /pairing (status={status}); transition not confirmed")


def setup_device(commands, interface=None):
    for link, address in usable(inventory(commands)):
        if interface and link.name != interface:
            continue
        match = re.fullmatch(r"WiZConfig_([0-9a-fA-F]{4})", link.ssid)
        if not match:
            continue
        for peer in dict.fromkeys(gateway(commands, link) + ["192.168.56.1"]):
            try:
                data = request(address, peer, "/device")
                identity = identify(data)
                if not identity.endswith(match.group(1).lower()):
                    continue
                return link, address, peer, identity
            except (RuntimeError, ValueError):
                continue
    raise RuntimeError("Connect to WiZConfig_xxxx and obtain an IPv4 address first")


def udp_candidates(address):
    found = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((str(address.ip), 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(0.2)
        sock.sendto(b'{"method":"getSystemConfig","params":{}}',
                    (str(address.network.broadcast_address), 38899))
        deadline = time.monotonic() + 0.4
        while time.monotonic() < deadline:
            try:
                data, peer = sock.recvfrom(8192)
                result = json.loads(data).get("result", {})
                if peer[1] == 38899 and IPv4Address(peer[0]) in address.network:
                    found.add((peer[0], mac(result.get("mac"))))
            except (TimeoutError, ValueError, TypeError, AttributeError):
                continue
    return found


def confirm(address, identity, timeout=30):
    """A setup HTTP 200 is not proof that local WiZ control is operational."""
    packet = b'{"method":"getPilot","params":{}}'
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((str(address.ip), 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        next_send = 0
        while time.monotonic() < deadline:
            if time.monotonic() >= next_send:
                sock.sendto(packet, (str(address.network.broadcast_address), 38899))
                next_send = time.monotonic() + 1
            sock.settimeout(min(0.5, max(0.01, deadline - time.monotonic())))
            try:
                raw, peer = sock.recvfrom(8192)
                reply = json.loads(raw)
                if (peer[1] == 38899 and IPv4Address(peer[0]) in address.network
                        and peer[0] != str(address.ip) and reply.get("method") == "getPilot"
                        and mac(reply.get("result", {}).get("mac")) == identity):
                    return peer[0]
            except (TimeoutError, ValueError, TypeError, AttributeError):
                continue
    raise RuntimeError("Device accepted /complete but did not respond to getPilot; local pairing is not confirmed")


def finish(commands, identity, timeout=120, device_ip=None, target_ssid=None):
    deadline = time.monotonic() + timeout
    print("Searching for the device...", flush=True)
    while time.monotonic() < deadline:
        networks = [(link, address) for link, address in usable(inventory(commands))
                    if not link.ssid.startswith("WiZConfig_")
                    and (not link.wireless or not link.ssid or link.ssid == target_ssid)]
        cached = neighbors(commands)
        for link, address in networks:
            candidates = set()
            if device_ip:
                candidates.add(device_ip)
            for iface, ip, value in cached:
                if iface == link.name:
                    try:
                        if mac(value) == identity:
                            candidates.add(ip)
                    except ValueError:
                        continue
            try:
                candidates.update(ip for ip, value in udp_candidates(address) if value == identity)
            except OSError:
                pass
            # TCP probes also find devices that have not enabled local UDP yet.
            if not device_ip and address.network.num_addresses <= 4096:
                candidates.update(str(ip) for ip in address.network.hosts() if ip != address.ip)

            def probe(ip):
                if found.is_set() or time.monotonic() >= deadline:
                    return None
                try:
                    data = request(address, ip, "/device", timeout=min(0.6, max(0.01, deadline - time.monotonic())))
                    if identify(data) == identity and data["status"] == 5:
                        found.set()
                        return ip
                except (RuntimeError, ValueError):
                    pass
                return None

            found = threading.Event()
            with ThreadPoolExecutor(max_workers=32) as pool:
                for ip in pool.map(probe, sorted(candidates)):
                    if ip:
                        # Recheck full identity, not just the four-character suffix.
                        try:
                            device = request(address, ip, "/device")
                            if identify(device) != identity or device["status"] != 5:
                                continue
                        except (RuntimeError, ValueError):
                            continue
                        print(f"Device's IP is {ip}.", flush=True)
                        print("Sending /complete...", flush=True)
                        try:
                            request(address, ip, "/complete", {})
                        except RuntimeError:
                            continue
                        print("Waiting for local WiZ confirmation...", flush=True)
                        ip = confirm(address, identity, min(30, max(0.1, deadline - time.monotonic())))
                        save_device(identity, ip)
                        return ip
            if time.monotonic() >= deadline:
                break
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise RuntimeError("Device was not found in connected setup state; check the network or use --device-ip")
