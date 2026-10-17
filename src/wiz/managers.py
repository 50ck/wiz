"""Existing Wi-Fi managers; temporary association with deterministic rollback."""
import configparser
import getpass
import os
import platform
import re
import shutil
import signal
import time
import uuid
from dataclasses import replace
from pathlib import Path
from ipaddress import IPv4Interface

from .pairing import generate_pairing_payload, validate_credentials
from .protocol import finish, finish_many, request, setup_device, wait_for_setup_exit
from .system import CommandError, inventory


def plaintext(value):
    return value if (isinstance(value, str) and 8 <= len(value.encode()) <= 63
                     and "\0" not in value and value != "*") else ""


def wpa_string(value):
    """Decode quoted supplicant strings or hex SSIDs, not derived hex PSKs."""
    if value.startswith('"') and value.endswith('"'):
        def unescape(match):
            value = match.group(1)
            return (bytes.fromhex(value[1:].decode()) if value.startswith(b"x") else
                    {b"n": b"\n", b"r": b"\r", b"t": b"\t"}.get(value, value))
        try:
            return re.sub(rb"\\(x[0-9a-fA-F]{2}|.)", unescape, value[1:-1].encode()).decode()
        except UnicodeError:
            return ""
    try:
        return bytes.fromhex(value).decode()
    except (ValueError, UnicodeError):
        return ""


def wpa_password(text, ssid):
    for block in re.findall(r"network\s*=\s*\{(.*?)\}", text, re.S):
        fields = dict(re.findall(r'(?m)^\s*(ssid|psk)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s#]+)', block))
        if wpa_string(fields.get("ssid", "")) == ssid:
            secret = fields.get("psk", "")
            if secret.startswith('"'):
                return plaintext(wpa_string(secret))
    return ""


def iwd_password(text):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
        # ConfigParser trims significant trailing spaces from string values.
        # iwd's keyfile syntax preserves them; recover the raw value instead.
        section = re.search(r"(?ms)^\[Security\][ \t]*\r?\n(.*?)(?=^\[|\Z)", text)
        field = re.search(r"(?m)^[ \t]*Passphrase[ \t]*=[ \t]*(.*)$", section.group(1)) if section else None
        value = field.group(1).rstrip("\r") if field else ""
        value = re.sub(r"\\([strn\\])", lambda m: {
            "s": " ", "t": "\t", "r": "\r", "n": "\n", "\\": "\\"
        }[m.group(1)], value)
        return plaintext(value)
    except configparser.Error:
        return ""


def control_value(text, key):
    match = re.search(r"(?m)^" + re.escape(key) + r"=(.*)$", text)
    return match.group(1) if match else ""


class NativeWifi:
    """Open WiZConfig association on an idle interface, without a Wi-Fi daemon."""
    name = "native Wi-Fi"

    def __init__(self, commands, link):
        if link.ssid or link.addresses:
            raise RuntimeError("An unmanaged Wi-Fi interface must be idle; use manual pairing")
        self.commands, self.link = commands, link
        self.address = IPv4Interface("192.168.56.2/24")
        self.changed = False
        links = inventory(commands)
        if not any(other.name != link.name and not other.wireless and other.up
                   and any(not address.ip.is_loopback for address in other.addresses) for other in links):
            raise RuntimeError("Native unattended pairing needs an active wired connection")
        for other in links:
            if other.name != link.name and other.up and any(
                    address.network.overlaps(self.address.network) for address in other.addresses):
                raise RuntimeError("The WiZConfig subnet overlaps another active interface")
        tool = "ifconfig" if platform.system() == "FreeBSD" else "iw"
        if not shutil.which(tool):
            raise RuntimeError(f"Native Wi-Fi requires the existing {tool} command")

    def password(self, ssid):
        return ""  # No manager/profile exists; ask for the destination password.

    def scan(self):
        if platform.system() == "FreeBSD":
            output = self.commands.run("ifconfig", self.link.name, "scan",
                                       privileged=True, timeout=12)
        else:
            output = self.commands.run("iw", "dev", self.link.name, "scan",
                                       privileged=True, timeout=12)
        return sorted(set(re.findall(r"\bWiZConfig_[0-9a-fA-F]{4}\b", output)))

    def connect(self, ssid):
        previous = self.changed
        self.changed = True
        if platform.system() == "FreeBSD":
            self.commands.run("ifconfig", self.link.name, "ssid", ssid, privileged=True)
            if not previous:
                self.commands.run("ifconfig", self.link.name, "inet", str(self.address), "alias",
                                  privileged=True)
        else:
            if previous:
                self.commands.run("iw", "dev", self.link.name, "disconnect", privileged=True, optional=True)
            self.commands.run("iw", "dev", self.link.name, "connect", ssid, privileged=True)
            if not previous:
                self.commands.run("ip", "address", "add", str(self.address), "dev", self.link.name,
                                  privileged=True)

    def restore(self):
        if not self.changed:
            return
        for current in inventory(self.commands):
            if current.name == self.link.name and self.address in current.addresses:
                if platform.system() == "FreeBSD":
                    self.commands.run("ifconfig", self.link.name, "inet", str(self.address.ip), "-alias",
                                      privileged=True)
                else:
                    self.commands.run("ip", "address", "del", str(self.address), "dev", self.link.name,
                                      privileged=True)
        if platform.system() == "FreeBSD":
            self.commands.run("ifconfig", self.link.name, "ssid", "", privileged=True)
        else:
            self.commands.run("iw", "dev", self.link.name, "disconnect", privileged=True, optional=True)
        self.changed = False


class NetworkManager:
    name = "NetworkManager"

    def __init__(self, commands, link):
        self.commands, self.link = commands, link
        self.original = commands.run("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", link.name)
        self.original = "" if self.original == "--" else self.original
        if self.original:
            ssid = commands.run("nmcli", "-g", "802-11-wireless.ssid", "connection", "show",
                                "uuid", self.original, optional=True)
            mode = commands.run("nmcli", "-g", "802-11-wireless.mode", "connection", "show",
                                "uuid", self.original, optional=True)
            self.link = replace(link, ssid=ssid or link.ssid,
                                mode="AP" if mode == "ap" else link.mode)
        self.temporary = str(uuid.uuid4())
        self.created = False

    def password(self, ssid):
        if self.original:
            actual = self.commands.run("nmcli", "-g", "802-11-wireless.ssid", "connection", "show",
                                       "uuid", self.original, optional=True)
            if actual == ssid:
                return plaintext(self.commands.run("nmcli", "--show-secrets", "-g",
                    "802-11-wireless-security.psk", "connection", "show", "uuid", self.original,
                    privileged=True, optional=True))
        # A wired host may still have a saved profile for the requested SSID.
        profiles = self.commands.run("nmcli", "-g", "UUID", "connection", "show", optional=True)
        for profile in profiles.splitlines():
            actual = self.commands.run("nmcli", "-g", "802-11-wireless.ssid", "connection", "show",
                                       "uuid", profile, optional=True)
            if actual == ssid:
                return plaintext(self.commands.run("nmcli", "--show-secrets", "-g",
                    "802-11-wireless-security.psk", "connection", "show", "uuid", profile,
                    privileged=True, optional=True))
        return ""

    def scan(self):
        output = self.commands.run("nmcli", "-g", "SSID", "device", "wifi", "list",
                                   "ifname", self.link.name, "--rescan", "yes", timeout=12)
        return sorted(set(re.findall(r"(?m)^WiZConfig_[0-9a-fA-F]{4}$", output)))

    def connect(self, ssid):
        if self.created:
            self.commands.run("nmcli", "connection", "modify", "uuid", self.temporary,
                              "802-11-wireless.ssid", ssid, privileged=True)
        else:
            self.commands.run("nmcli", "connection", "add", "type", "wifi", "ifname", self.link.name,
                              "con-name", "wiz-" + self.temporary, "connection.uuid", self.temporary,
                              "ssid", ssid, "connection.autoconnect", "no", "ipv4.method", "auto",
                              "ipv4.never-default", "yes", "ipv4.ignore-auto-dns", "yes",
                              "ipv6.method", "disabled", privileged=True)
        self.created = True
        self.commands.run("nmcli", "--wait", "30", "connection", "up", "uuid", self.temporary,
                          "ifname", self.link.name, privileged=True, timeout=35)

    def restore(self):
        if not self.created:
            return
        try:
            if self.original:
                self.commands.run("nmcli", "--wait", "30", "connection", "up", "uuid", self.original,
                                  "ifname", self.link.name, privileged=True, timeout=35)
            else:
                self.commands.run("nmcli", "connection", "down", "uuid", self.temporary, privileged=True)
        finally:
            self.commands.run("nmcli", "connection", "delete", "uuid", self.temporary, privileged=True)
            self.created = False


class Iwd:
    name = "iwd"

    def __init__(self, commands, link):
        self.commands, self.link = commands, link
        self.changed, self.temporary = False, ""
        self.setup_address = None
        self.owned_networks = set()

    def password(self, ssid):
        # iwd uses =hex when SSID bytes are unsuitable for a literal filename.
        names = ["=" + ssid.encode().hex()]
        if re.fullmatch(r"[a-zA-Z0-9 _-]+", ssid):
            names.insert(0, ssid)
        for name in names:
            secret = iwd_password(self.commands.read(Path("/var/lib/iwd") / (name + ".psk")))
            if secret:
                return secret
        return ""

    def scan(self):
        self.commands.run("iwctl", "station", self.link.name, "scan", privileged=True,
                          timeout=12, optional=True)
        # Scan starts asynchronously; get-networks alone can return stale APs.
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            status = self.commands.run("iwctl", "station", self.link.name, "show",
                                       privileged=True, timeout=3)
            if re.search(r"(?m)^\s*Scanning\s+no\s*$", status):
                break
            time.sleep(0.25)
        else:
            raise CommandError("iwd scan did not finish within 12 seconds")
        output = self.commands.run("iwctl", "station", self.link.name, "get-networks", privileged=True)
        return sorted(set(re.findall(r"\bWiZConfig_[0-9a-fA-F]{4}\b", output)))

    def connect(self, ssid):
        self.changed = True
        known = self.commands.run("iwctl", "known-networks", "list", privileged=True)
        self.temporary = "" if re.search(r"\b" + re.escape(ssid) + r"\b", known) else ssid
        if self.temporary:
            self.owned_networks.add(self.temporary)
        for attempt in range(2):
            try:
                self.commands.run("iwctl", "--dont-ask", "station", self.link.name, "connect", ssid,
                                  privileged=True, timeout=35)
                return
            except CommandError:
                if attempt:
                    raise CommandError("iwd could not connect to WiZConfig after rescanning") from None
                if ssid not in self.scan():
                    raise CommandError("WiZConfig is no longer visible; return the device to manual pairing mode") from None

    def restore(self):
        if not self.changed:
            return
        try:
            if self.setup_address is not None:
                self.commands.run("ip", "address", "del", str(self.setup_address), "dev", self.link.name,
                                  privileged=True)
                self.setup_address = None
            if self.link.ssid:
                self.commands.run("iwctl", "--dont-ask", "station", self.link.name, "connect", self.link.ssid,
                                  privileged=True, timeout=35)
            else:
                status = self.commands.run("iwctl", "station", self.link.name, "show", privileged=True)
                if not re.search(r"(?m)^\s*State\s+disconnected\s*$", status):
                    self.commands.run("iwctl", "station", self.link.name, "disconnect", privileged=True)
        finally:
            for network in sorted(self.owned_networks):
                self.commands.run("iwctl", "known-networks", network, "forget",
                                  privileged=True, optional=True)
            self.owned_networks.clear()
        self.changed = False


class Supplicant:
    name = "wpa_supplicant"

    def __init__(self, commands, link):
        self.commands, self.link = commands, link
        status = self.call("status")
        self.original = control_value(status, "id")
        rows = self.call("list_networks").splitlines()
        self.enabled = [r.split("\t")[0] for r in rows if re.match(r"^\d+\t", r)
                        and "[DISABLED]" not in r]
        self.temporary = ""
        self.changed = False

    def call(self, *args, optional=False):
        output = self.commands.run("wpa_cli", "-i", self.link.name, *args,
                                   privileged=True, optional=optional)
        if "FAIL" in output or "UNKNOWN COMMAND" in output:
            if optional:
                return ""
            raise CommandError("wpa_supplicant rejected the command")
        return output

    def password(self, ssid):
        for row in self.call("list_networks").splitlines():
            fields = row.split("\t")
            if len(fields) >= 2 and fields[0].isdigit() and fields[1] == ssid:
                secret = self.call("get_network", fields[0], "psk", optional=True)
                if secret.startswith('"'):
                    value = plaintext(wpa_string(secret))
                    if value:
                        return value
        paths = {"/etc/wpa_supplicant.conf", "/etc/wpa_supplicant/wpa_supplicant.conf",
                 f"/etc/wpa_supplicant/wpa_supplicant-{self.link.name}.conf"}
        # Include the actual -c path from a running Linux supplicant.
        if platform.system() == "Linux":
            for entry in Path("/proc").glob("[0-9]*/comm"):
                try:
                    if entry.read_text().strip() != "wpa_supplicant":
                        continue
                    args = entry.with_name("cmdline").read_bytes().decode().split("\0")
                    for index, arg in enumerate(args):
                        if arg == "-c" and index + 1 < len(args):
                            paths.add(args[index + 1])
                        elif arg.startswith("-c") and len(arg) > 2:
                            paths.add(arg[2:])
                except (OSError, UnicodeError):
                    continue
        for path in paths:
            value = wpa_password(self.commands.read(path), ssid)
            if value:
                return value
        return ""

    def scan(self):
        self.call("scan", optional=True)  # BUSY means an existing scan is in progress.
        output = self.call("scan_results")
        return sorted(set(re.findall(r"\bWiZConfig_[0-9a-fA-F]{4}\b", output)))

    def connect(self, ssid):
        self.changed = True
        if self.temporary:
            self.call("remove_network", self.temporary)
            self.temporary = ""
        output = self.call("add_network")
        match = re.search(r"(?m)^(\d+)$", output)
        if not match:
            raise CommandError("Cannot create temporary supplicant network")
        self.temporary = match.group(1)
        self.call("set_network", self.temporary, "ssid", ssid.encode().hex())
        self.call("set_network", self.temporary, "key_mgmt", "NONE")
        self.call("select_network", self.temporary)

    def restore(self):
        if not self.changed:
            return
        if self.temporary:
            self.call("remove_network", self.temporary)
        if self.original:
            self.call("select_network", self.original)
        else:
            self.call("disconnect")
        for identifier in self.enabled:
            self.call("enable_network", identifier)
        self.temporary = ""
        self.changed = False


def detect(commands, link):
    state = commands.run("nmcli", "-g", "GENERAL.STATE", "device", "show", link.name,
                         optional=True, timeout=3)
    if state and not state.startswith(("10 ", "20 ")):
        return NetworkManager(commands, link)
    if commands.run("iwctl", "station", link.name, "show", optional=True, timeout=3):
        return Iwd(commands, link)
    status = commands.run("wpa_cli", "-i", link.name, "status", privileged=True,
                          optional=True, timeout=3)
    if "wpa_state=" in status:
        return Supplicant(commands, link)
    return NativeWifi(commands, link)


def dhcp_refresh(commands, manager):
    if isinstance(manager, (NetworkManager, NativeWifi)):
        return  # These adapters already configure IP; don't involve other daemons.
    # Leave existing IP daemons in charge; never launch or stop a global daemon.
    if platform.system() == "FreeBSD":
        if shutil.which("dhclient"):
            commands.run("service", "dhclient", "restart", manager.link.name,
                         privileged=True, timeout=35)
        return
    processes = commands.run("ps", "-axo", "comm", optional=True).splitlines()
    processes = {Path(p.strip()).name for p in processes}
    if "dhcpcd" in processes and shutil.which("dhcpcd"):
        commands.run("dhcpcd", "-n", manager.link.name, privileged=True, timeout=20)
    elif "systemd-networkd" in processes and shutil.which("networkctl"):
        commands.run("networkctl", "reconfigure", manager.link.name, privileged=True)
    elif isinstance(manager, Iwd) and not manager.link.ssid and not manager.link.addresses:
        links = inventory(commands)
        current = next((link for link in links if link.name == manager.link.name), None)
        if current is None or not re.fullmatch(r"WiZConfig_[0-9a-fA-F]{4}", current.ssid):
            return
        if current.addresses or not any(link.up and not link.wireless and link.addresses
                                        and link.name != current.name for link in links):
            return
        address = IPv4Interface("192.168.56.2/24")
        if any(link.up and link.name != current.name and any(
                other.network.overlaps(address.network) for other in link.addresses) for link in links):
            raise CommandError("The WiZConfig subnet overlaps another active interface")
        # Same known-subnet fallback as NativeWifi, for a dedicated idle iwd radio.
        # Only this address is owned; no default route, DNS or daemon changes.
        print("Configuring temporary WiZConfig IPv4 address...", flush=True)
        commands.run("ip", "address", "add", str(address), "dev", current.name, privileged=True)
        manager.setup_address = address
    # iwd's built-in IP configuration and link-aware clients need no extra call.


def restore(commands, manager):
    previous = signal.getsignal(signal.SIGINT)
    term = signal.getsignal(signal.SIGTERM)
    try:
        # A second interrupt must not strand the interface during rollback.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        changed = bool(getattr(manager, "created", False) or getattr(manager, "changed", False)
                       or getattr(manager, "temporary", ""))
        manager.restore()
        if changed and not isinstance(manager, (NetworkManager, NativeWifi)):
            # Remove the setup lease only on the selected interface; never flush
            # addresses or routes on another interface.
            for current in inventory(commands):
                if current.name != manager.link.name:
                    continue
                for address in current.addresses:
                    if any(address.ip in old.network for old in manager.link.addresses):
                        continue
                    if platform.system() == "FreeBSD":
                        commands.run("ifconfig", current.name, "inet", str(address.ip), "-alias",
                                     privileged=True)
                    else:
                        commands.run("ip", "address", "del", str(address), "dev", current.name,
                                     privileged=True)
            if manager.link.ssid:
                dhcp_refresh(commands, manager)
        if not manager.link.up:
            if platform.system() == "FreeBSD":
                commands.run("ifconfig", manager.link.name, "down", privileged=True)
            else:
                commands.run("ip", "link", "set", "dev", manager.link.name, "down", privileged=True)
    except (CommandError, OSError):
        raise RuntimeError("Could not restore the original interface; reconnect it with your Wi-Fi manager") from None
    finally:
        signal.signal(signal.SIGINT, previous)
        signal.signal(signal.SIGTERM, term)


def wait_original(commands, manager, timeout=45):
    if not manager.link.ssid:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for link in inventory(commands):
            correct_network = any(address.ip in old.network for address in link.addresses
                                  for old in manager.link.addresses)
            if (link.name == manager.link.name and link.ssid == manager.link.ssid and link.addresses
                    and (correct_network or not manager.link.addresses)):
                return
        time.sleep(0.5)
    raise RuntimeError("Original Wi-Fi connection did not recover an IPv4 address")


def unattended(commands, args):
    links = [link for link in inventory(commands) if link.wireless]
    if args.interface:
        links = [link for link in links if link.name == args.interface]
    else:
        connected = [link for link in links if link.ssid and link.mode != "AP"]
        if connected:
            links = connected
    if len(links) != 1:
        raise RuntimeError("Select one Wi-Fi interface with --interface")
    link = links[0]
    if link.mode and link.mode != "managed":
        raise RuntimeError("Unattended pairing requires a managed Wi-Fi interface, not an AP")
    if link.ssid.startswith("WiZConfig_"):
        raise RuntimeError("Return to your normal network before unattended pairing")
    commands.authorize()
    manager = detect(commands, link)
    link = manager.link
    if link.mode == "AP":
        raise RuntimeError("Unattended pairing requires a managed Wi-Fi interface, not an AP")
    if link.ssid.startswith("WiZConfig_"):
        raise RuntimeError("Return to your normal network before unattended pairing")
    print(f"Using {link.name} ({manager.name}).", flush=True)
    ssid = link.ssid or input("Type the SSID to connect: ")
    password = manager.password(ssid) or getpass.getpass(f"Type the password for {ssid}: ")
    validate_credentials(ssid, password)
    payload = generate_pairing_payload(ssid, password)
    print("Make sure the device is in manual pairing mode (purple blinking).")
    print("wiz will detect it automatically. Scanning for 1 minute...", flush=True)
    restored = False
    try:
        if not link.up:
            if platform.system() == "FreeBSD":
                commands.run("ifconfig", link.name, "up", privileged=True)
            else:
                commands.run("ip", "link", "set", "dev", link.name, "up", privileged=True)
        deadline = time.monotonic() + 60
        found = []
        while time.monotonic() < deadline:
            found = manager.scan()
            if found:
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        if not found:
            raise RuntimeError("WiZConfig_xxxx was not found within 1 minute")
        found = sorted(set(found))
        if len(found) > 32:
            raise RuntimeError("At most 32 devices can be paired together")
        if len(found) > 1 and args.device_ip:
            raise RuntimeError("--device-ip can only be used with one device")
        identities, errors = [], []
        print(f"Found {len(found)} device(s).", flush=True)
        for index, network in enumerate(found):
            try:
                print(f"Connecting to {network} ({index + 1}/{len(found)})...", flush=True)
                if index and platform.system() == "Linux":
                    # Different devices share the setup gateway IP; drop only its old neighbor.
                    commands.run("ip", "neighbor", "del", peer, "dev", link.name,
                                 privileged=True, optional=True)
                manager.connect(network)
                dhcp_refresh(commands, manager)
                ready = time.monotonic() + 45
                setup = None
                while time.monotonic() < ready:
                    try:
                        setup = setup_device(commands, link.name)
                        if setup[0].ssid == network:
                            break
                        setup = None
                    except RuntimeError:
                        pass
                    time.sleep(0.5)
                if setup is None:
                    raise RuntimeError("WiZConfig association or IPv4 configuration failed")
                _, address, peer, identity = setup
                if identity in identities:
                    raise RuntimeError("The same device was detected twice")
                print(f"Sending /pairing to {network}...", flush=True)
                request(address, peer, "/pairing", payload if not index else generate_pairing_payload(ssid, password))
                print("POST /pairing: HTTP 200", flush=True)
                wait_for_setup_exit(address, peer, identity)
                identities.append(identity)
            except (RuntimeError, OSError) as error:
                if not identities:
                    raise
                errors.append(f"{network}: {error}")
                print(f"Pairing stopped at {network}; completing earlier devices first.", flush=True)
                break
        print("OK! Restoring the original connection...", flush=True)
        restore(commands, manager)
        restored = True
        wait_original(commands, manager)
    finally:
        if not restored:
            print("Restoring the original connection...", flush=True)
            restore(commands, manager)
    try:
        if len(identities) == 1:
            finish(commands, identities[0], args.timeout, args.device_ip, ssid)
        else:
            finish_many(commands, identities, args.timeout, args.device_ip, ssid)
    except (RuntimeError, OSError) as error:
        errors.append(str(error))
    if errors:
        raise RuntimeError("Batch pairing incomplete: " + "; ".join(errors))
    print("All set!")
