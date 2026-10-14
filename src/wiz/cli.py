"""Pair devices locally. Network changes are exclusive to unattended mode."""
import argparse
import getpass
import signal
import os
import shutil
import sys
from pathlib import Path
from ipaddress import IPv4Address

from .pairing import generate_pairing_payload, validate_credentials
from .protocol import finish, request, setup_device, wait_for_setup_exit
from .system import Commands


def local_control(args):
    from concurrent.futures import ThreadPoolExecutor
    from .config import read_devices
    from .control import PRESETS, color, mode, pilot_params, query, set_pilot
    from .system import inventory, usable

    if args.command == "list" and args.target == "modes":
        for preset in PRESETS:
            print(f"{preset['id']:>3}  {preset['label']}"
                  + (" [accessory required]" if preset["accessory"] else ""))
        return
    devices = read_devices()
    if args.command == "device":
        selected = next(((ip, record) for ip, record in devices.items()
                         if record["label"] == args.target), None)
        if selected is None:
            raise ValueError("Unknown device; use wiz list devices")
        if args.action == "mode":
            params = mode(args.value)
        elif args.action == "color":
            params = color(args.value)
        elif args.action == "brightness":
            params = pilot_params({"brightness": int(args.value)})
        else:
            params = {"state": args.action == "on"}
    elif not devices:
        print("No saved devices.")
        return
    sources = tuple(address for link, address in usable(inventory(Commands()))
                    if args.interface is None or link.name == args.interface)
    if args.command == "device":
        ip, record = selected
        set_pilot(ip, record["mac"], sources, params)
        print("OK")
        return

    def status(item):
        ip, record = item
        try:
            query(ip, record["mac"], sources)
            return "Online"
        except (OSError, RuntimeError, ValueError):
            return "Offline"

    with ThreadPoolExecutor(max_workers=len(devices)) as pool:
        for (ip, record), state in zip(devices.items(), pool.map(status, devices.items())):
            print(f"{record['label']}\t{record['mac']}\t{ip}\t{state}")


def elevate(argv):
    if os.geteuid() == 0:
        return
    tool = shutil.which("doas") or shutil.which("sudo")
    if not tool:
        raise RuntimeError("Unattended pairing requires root, doas or sudo")
    print(f"{Path(tool).name} will be required for this action", flush=True)
    launcher = Path(__file__).resolve().parents[2] / "wiz"
    os.execv(tool, [tool, sys.executable, str(launcher), *argv])


def manual(commands, args):
    ssid = input("Type the SSID to connect: ")
    password = getpass.getpass("Type the password: ")
    validate_credentials(ssid, password)
    # Fail before any network change if the crypto dependency is unavailable.
    payload = generate_pairing_payload(ssid, password)
    print("\n1. Put the device in manual pairing mode (purple blinking)")
    input('2. Connect to the device\'s access point. You can find it as "WiZConfig_xxxx". '
          "Once done, press Enter.")
    link, address, peer, identity = setup_device(commands, args.interface)
    print(f"Connected to {link.ssid}")
    print("Generating /pairing...")
    print("Sending /pairing...", flush=True)
    request(address, peer, "/pairing", payload)
    print("POST /pairing: HTTP 200")
    wait_for_setup_exit(address, peer, identity)
    print("OK!")
    input(f"\n3. Return to {ssid}. Once done, press Enter.")
    finish(commands, identity, args.timeout, args.device_ip, ssid)
    print(f"Success! The device is now paired with {ssid}.")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = argparse.ArgumentParser(prog="wiz", description="Pair and control WiZ devices locally")
    parser.add_argument("command", choices=("pair", "upair", "web", "list", "device"),
                        help="pair, upair, web, list devices/modes, or device LABEL ACTION [VALUE]")
    parser.add_argument("target", nargs="?", help="devices/modes or a configured device label")
    parser.add_argument("action", nargs="?", help="mode, color, brightness, off or on")
    parser.add_argument("value", nargs="?", help="Mode ID/name, color or brightness percent")
    parser.add_argument("-i", "--interface", help="Select a Wi-Fi interface when detection is ambiguous")
    parser.add_argument("--device-ip", type=lambda value: str(IPv4Address(value)),
                        help="Known device IPv4 address after joining the target network")
    parser.add_argument("--timeout", type=int, default=120, help="Discovery timeout in seconds")
    parser.add_argument("--port", type=int, default=24800, help="Web server port")
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("Timeout must be positive")
    if args.command == "list":
        if args.target not in ("devices", "modes") or args.action is not None:
            parser.error("Use wiz list devices or wiz list modes")
    elif args.command == "device":
        if not args.target or args.action not in ("mode", "color", "brightness", "off", "on"):
            parser.error("Use wiz device LABEL {mode|color|brightness|off|on} [VALUE]")
        if (args.action in ("mode", "color", "brightness")) != (args.value is not None):
            parser.error("mode, color and brightness require a value; off and on take none")
    elif args.target is not None:
        parser.error("Unexpected arguments")
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.command == "pair":
            manual(Commands(), args)
        elif args.command == "upair":
            elevate(argv)
            from .managers import unattended
            unattended(Commands(), args)
        elif args.command == "web":
            from .web import serve
            serve(args.interface, args.port)
        else:
            local_control(args)
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nWeb server stopped." if args.command == "web" else
              "\nPairing cancelled." if args.command in ("pair", "upair") else "\nCancelled.")
        return 130
    except (RuntimeError, ValueError) as error:
        print(f"Error: {error}")
        return 1
    except OSError:
        print("Operation failed. Check the network connection and required tools.")
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
