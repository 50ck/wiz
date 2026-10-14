"""Device records only; Wi-Fi credentials are never persisted."""
import configparser
import os
import tempfile
import pwd
from ipaddress import IPv4Address
from pathlib import Path


def user_home():
    if os.geteuid() == 0:
        user = os.environ.get("DOAS_USER") or os.environ.get("SUDO_USER")
        if user:
            try:
                account = pwd.getpwnam(user)
                return Path(account.pw_dir), (account.pw_uid, account.pw_gid)
            except KeyError:
                raise RuntimeError("Cannot identify the original user for device configuration") from None
    return Path.home(), None


def read_devices():
    from .protocol import mac as normalize_mac

    home, _ = user_home()
    path = home / ".config/wiz/config.ini"
    parser = configparser.ConfigParser(interpolation=None)
    devices, identities = {}, set()
    try:
        if not path.exists():
            return devices
        with path.open() as file:
            parser.read_file(file)
        for label in parser.sections():
            if not parser.has_option(label, "mac") and not parser.has_option(label, "ip"):
                continue
            identity = normalize_mac(parser.get(label, "mac"))
            ip = str(IPv4Address(parser.get(label, "ip")))
            if ip in devices or identity in identities:
                raise ValueError("Duplicate device IP or MAC")
            devices[ip] = {"label": label, "mac": identity}
            identities.add(identity)
        if len(devices) > 32:
            raise ValueError("Maximum 32 devices")
    except (OSError, configparser.Error, ValueError):
        raise RuntimeError("Invalid or unreadable device records in ~/.config/wiz/config.ini") from None
    return devices


def save_device(mac, ip):
    from .protocol import mac as normalize_mac

    mac, ip = normalize_mac(mac), str(IPv4Address(ip))
    home, owner = user_home()
    path = home / ".config/wiz/config.ini"
    config = configparser.ConfigParser(interpolation=None)
    try:
        if path.exists():
            with path.open() as file:
                config.read_file(file)
        section = next((name for name in config.sections()
                        if config.get(name, "mac", fallback="").lower().replace(":", "").replace("-", "") == mac), None)
        if section is None:
            index = 0
            while config.has_section(f"device{index}"):
                index += 1
            section = f"device{index}"
            config.add_section(section)
        config.set(section, "mac", mac)
        config.set(section, "ip", ip)
        for directory in (path.parent.parent, path.parent):
            if not directory.exists():
                directory.mkdir(mode=0o700)
                if owner is not None:
                    os.chown(directory, *owner)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as file:
                temporary = Path(file.name)
                os.chmod(temporary, 0o600)
                if owner is not None:
                    os.fchown(file.fileno(), *owner)
                config.write(file)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    except (OSError, configparser.Error):
        raise RuntimeError("Device paired, but ~/.config/wiz/config.ini could not be saved") from None
    return section
