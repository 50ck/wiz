# wiz

`wiz` is a local WiZ tool that supports WiZ's manual pairing mode, and its device management, such as changing colors and brightness through the web panel. All without using the official app for anything. Everything is in your network as it should be.

## install
Requires Python 3.11+ and your distribution's Python `cryptography` package.
- On Linux: `python3-cryptography` (Debian, Fedora, Void), `python-cryptography` (Arch), `dev-python/cryptography` (Gentoo).
- On FreeBSD: `pkg install python311 py311-cryptography` (or matching newer packages).

[!NOTE] 
Almost mandatory to block Internet access to the WiZ devices while allowing LAN communication for the UDP requests. When the device connects to the Internet, it goes to talk with the WiZ MQTT server, and after the MQTT server's response it causes the device to unpair automatically. I suspect it's because an invalid `hid`. Blocking Internet access for the device makes it work properly (lol).

After this, then:

```bash
git clone https://github.com/50ck/wiz
cd wiz
mkdir -p ~/.local/bin
ln -s "$PWD/wizbind" ~/.local/bin/wiz
```

Ensure ~/.local/bin is in your PATH.


## examples

```sh
wiz pair # manual setup with guided steps
wiz upair # unattended setup
wiz upair --interface wlan0
wiz web
```
