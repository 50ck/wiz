# wiz

`wiz` is a local WiZ tool that supports WiZ's manual pairing mode, and device management, such as changing colors and brightness through the local web control panel and CLI commands. All without using the official app for anything. Everything is in your network as it should be.

## How to install
Requires Python 3.11+ and your distribution's Python `cryptography` package.
- On Linux: `python3-cryptography` (Debian, Fedora, Void), `python-cryptography` (Arch), `dev-python/cryptography` (Gentoo).
- On FreeBSD: `pkg install python311 py311-cryptography` (or matching newer packages).

> [!NOTE] 
> Almost mandatory to **block Internet access to your WiZ devices** while allowing LAN communication for your local TCP and UDP requests.
>
> When the device connects to the Internet, it goes to talk with the WiZ MQTT server, and after the MQTT server's response it causes the device to unpair automatically. I suspect it's because an invalid home ID. Blocking Internet access for the device makes it work properly (lol).

After this, then:

```bash
git clone https://github.com/50ck/wiz
cd wiz
mkdir -p ~/.local/bin
ln -s "$PWD/wizbind" ~/.local/bin/wiz
```

Ensure `~/.local/bin` is in your PATH.


## Examples

```bash
# Pairing
wiz pair                              # manual setup with guided steps
wiz upair                             # unattended setup, pretty cool
wiz upair --interface wlan0
```

```bash
# Management
wiz web                               # you can use a local web to control devices
wiz list devices                      # saved devices and online/offline status
wiz list modes                        # mode IDs and names

wiz device device0 mode 16            # sets scene: relax
wiz device device0 color '#ff00ff'    # sets color: magenta
wiz device device0 color '#ff00ff66'  # sets color: magenta, 40% brightness
wiz device device0 brightness 60      # sets brightness in percentage
wiz device device0 off
wiz device device0 on
```
