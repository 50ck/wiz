"""Read-only interface inspection and bounded root-only network commands."""
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Interface
from pathlib import Path


class CommandError(RuntimeError):
    pass


class Commands:
    def authorize(self):
        if os.geteuid() != 0:
            raise CommandError("Unattended pairing must run as root")

    def run(self, *args, privileged=False, optional=False, timeout=15, input=None):
        command = list(args)
        if command[0] == "nmcli":
            command[1:1] = ["--escape", "no", "--colors", "no"]
        if privileged:
            self.authorize()
        try:
            result = subprocess.run(command, input=input, text=True, capture_output=True,
                                    timeout=timeout, env={**os.environ, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired):
            if optional:
                return ""
            raise CommandError(f"{args[0]} unavailable or timed out") from None
        if result.returncode:
            if optional:
                return ""
            # Tool output may contain credentials; never include it in errors.
            raise CommandError(f"{args[0]} failed")
        return result.stdout.rstrip("\n")

    def read(self, path):
        try:
            return Path(path).read_text()
        except PermissionError:
            return self.run("cat", "--", str(path), privileged=True, optional=True)
        except (OSError, UnicodeError):
            return ""


@dataclass(frozen=True)
class Link:
    name: str
    up: bool
    wireless: bool
    addresses: tuple
    ssid: str = ""
    mode: str = ""


def parse_ifconfig(text):
    links = []
    for match in re.finditer(r"(?m)^([\w.-]+): (.*(?:\n[ \t].*)*)", text):
        name, block = match.groups()
        addresses = []
        for ip, mask in re.findall(r"\binet (\d+\.\d+\.\d+\.\d+) netmask (\S+)", block):
            try:
                if mask.startswith("0x"):
                    from ipaddress import IPv4Address
                    mask = str(IPv4Address(int(mask, 16)))
                addresses.append(IPv4Interface(f"{ip}/{mask}"))
            except ValueError:
                continue
        ssid = re.search(r'\bssid ("(?:[^"\\]|\\.)*"|.*?) channel\b', block)
        value = ssid.group(1).strip().strip('"') if ssid else ""
        mode = "AP" if "<hostap>" in block else "managed"
        links.append(Link(name, "UP" in block.split("\n")[0],
                          "IEEE 802.11" in block or bool(ssid), tuple(addresses), value, mode))
    return links


def inventory(commands):
    if platform.system() == "FreeBSD":
        return parse_ifconfig(commands.run("ifconfig", "-a"))
    if platform.system() != "Linux":
        raise RuntimeError("Supported systems: Linux and FreeBSD")
    try:
        records = json.loads(commands.run("ip", "-j", "address", "show"))
    except ValueError:
        raise RuntimeError("Invalid interface information from ip") from None
    wireless = commands.run("iw", "dev", optional=True)
    wifi_names = set(re.findall(r"Interface (\S+)", wireless))
    nm_devices = commands.run("nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status", optional=True)
    wifi_names.update(line.rsplit(":", 1)[0] for line in nm_devices.splitlines() if line.endswith(":wifi"))
    links = []
    for record in records:
        name = record["ifname"]
        wifi = (name in wifi_names or Path(f"/sys/class/net/{name}/wireless").exists()
                or Path(f"/sys/class/net/{name}/phy80211").exists())
        info = commands.run("iw", "dev", name, "info", optional=True) if wifi else ""
        ssid = re.search(r"(?m)^\s*ssid (.+)$", info)
        mode = re.search(r"(?m)^\s*type (.+)$", info)
        if wifi and not ssid:
            status = commands.run("wpa_cli", "-i", name, "status", optional=True, timeout=3)
            ssid = re.search(r"(?m)^ssid=(.+)$", status)
        if wifi and not ssid:
            status = commands.run("iwctl", "station", name, "show", optional=True, timeout=3)
            ssid = re.search(r"(?m)^\s*Connected network\s+(.+?)\s*$", status)
        if wifi and not ssid:
            profile = commands.run("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", name, optional=True)
            if profile and profile != "--":
                value = commands.run("nmcli", "-g", "802-11-wireless.ssid", "connection", "show",
                                     "uuid", profile, optional=True)
                ssid = re.match(r"(.+)", value) if value else None
        addresses = tuple(IPv4Interface(f"{a['local']}/{a['prefixlen']}")
                          for a in record.get("addr_info", []) if a.get("family") == "inet")
        links.append(Link(name, "UP" in record.get("flags", []), wifi, addresses,
                          ssid.group(1) if ssid else "", mode.group(1) if mode else ""))
    return links


def usable(links):
    return [(link, address) for link in links if link.up for address in link.addresses
            if not address.ip.is_loopback and not address.ip.is_link_local]


def gateway(commands, link):
    if platform.system() == "Linux":
        options = commands.run("nmcli", "-g", "DHCP4.OPTION", "device", "show", link.name,
                               optional=True)
        routers = re.findall(r"(?m)^routers\s*=\s*([0-9.]+)", options)
        rows = commands.run("ip", "-j", "-4", "route", "show", "dev", link.name,
                            optional=True)
        try:
            return routers + [row["gateway"] for row in json.loads(rows or "[]") if "gateway" in row]
        except (ValueError, TypeError):
            return routers
    output = commands.run("netstat", "-rn", "-f", "inet", optional=True)
    return [line.split()[1] for line in output.splitlines()
            if line.split() and line.split()[0] == "default" and link.name in line.split()]


def neighbors(commands):
    if platform.system() == "Linux":
        output = commands.run("ip", "-j", "-4", "neighbor", "show", optional=True)
        try:
            return [(r["dev"], r["dst"], r.get("lladdr", "")) for r in json.loads(output or "[]")]
        except (ValueError, KeyError, TypeError):
            return []
    output = commands.run("arp", "-an", optional=True)
    return [(m.group(3), m.group(1), m.group(2)) for m in re.finditer(
        r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on (\S+)", output)]
