"""WiZ manual pairing, validated against the captured official request.

This standalone implementation retains the public constants and validated
encoding from wizbind. Pairing always uses a nonzero local Home ID of 420.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time


def validate_credentials(ssid: str, password: str) -> tuple[bytes, bytes]:
    network, secret = ssid.encode("utf-8"), password.encode("utf-8")
    if not 1 <= len(network) <= 32 or not 8 <= len(secret) <= 63:
        raise ValueError("SSID must be 1–32 bytes and WPA2 password 8–63 bytes")
    if b"\0" in network or b"\0" in secret:
        raise ValueError("Embedded NUL is unsupported")
    return network, secret


# Public certificate shared by the audited firmware builds; no private key.
PUBLIC_CERTIFICATE = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\n"
    b"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
    b"DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\n"
    b"SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\n"
    b"GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
    b"AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\n"
    b"q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\n"
    b"SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\n"
    b"Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\n"
    b"a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n"
    b"/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\n"
    b"AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\n"
    b"CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\n"
    b"bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\n"
    b"c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\n"
    b"VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\n"
    b"ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\n"
    b"MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\n"
    b"Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\n"
    b"AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\n"
    b"uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\n"
    b"wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\n"
    b"X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\n"
    b"PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\n"
    b"KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n"
    b"-----END CERTIFICATE-----"
)


def generate_pairing_payload(
    ssid: str,
    password: str,
    *,
    iv: bytes | None = None,
    offsets: tuple[int, int] = (15, 1),
    encrypted_prefix_length: int | None = None,
    env: str = "pro",
    reg: str = "eu",
    ts: int | None = None,
) -> dict[str, object]:
    """Firmware-compatible payload; deterministic inputs reproduce captured bytes.

    The local partition rule is a policy, not a recovered app algorithm. The
    receiver concatenates decrypted enc_pwd and plaintext pwd. Choose a UTF-8
    boundary near the midpoint, keeping the plaintext suffix <=32 bytes.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise RuntimeError(
            "Pairing requires Python cryptography; install your distribution's package"
        ) from None

    ssid_bytes, password_bytes = validate_credentials(ssid, password)
    if b"\0" in ssid_bytes or b"\0" in password_bytes:
        raise ValueError("Embedded NUL is unsupported")
    if iv is None:
        iv = secrets.token_bytes(16)
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("IV must contain sixteen bytes")
    line, column = offsets
    if (
        type(line) is not int
        or type(column) is not int
        or not 1 <= line <= 24
        or not 0 <= column <= 47
    ):
        raise ValueError("Invalid certificate offsets")
    material = PUBLIC_CERTIFICATE.split(b"\n")[line][column : column + 16]
    if len(material) != 16:
        raise ValueError("Invalid certificate slice")
    key = hashlib.md5(material, usedforsecurity=False).hexdigest().encode("ascii")
    if encrypted_prefix_length is None:
        encrypted_prefix_length = (len(password_bytes) + 1) // 2
        while (
            encrypted_prefix_length < len(password_bytes)
            and password_bytes[encrypted_prefix_length] & 0xC0 == 0x80
        ):
            encrypted_prefix_length += 1
    if type(
        encrypted_prefix_length
    ) is not int or not 0 <= encrypted_prefix_length <= len(password_bytes):
        raise ValueError("Invalid encrypted prefix length")
    prefix = password_bytes[:encrypted_prefix_length]
    suffix = password_bytes[encrypted_prefix_length:]
    try:
        prefix.decode("utf-8")
        pwd = suffix.decode("utf-8")
    except UnicodeError:
        raise ValueError("Partition must be a UTF-8 boundary") from None
    if len(suffix) > 32:
        raise ValueError("Plaintext suffix exceeds firmware limit")
    if (
        env not in ("pro", "")
        or reg not in ("eu", "")
    ):
        raise ValueError("Unsupported pairing metadata")
    timestamp = int(time.time()) if ts is None else ts
    if type(timestamp) is not int or not 0 <= timestamp <= 0x7FFFFFFFFFFFFFFF:
        raise ValueError("Invalid timestamp")

    def encrypt(value: bytes) -> str:
        padding = 16 - len(value) % 16
        padded = value + bytes((padding,)) * padding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return base64.b64encode(cipher.update(padded) + cipher.finalize()).decode(
            "ascii"
        )

    return {
        "enc_ssid": encrypt(ssid_bytes),
        "enc_pwd": encrypt(prefix),
        "pwd": pwd,
        "offsets": [line, column],
        "iv": base64.b64encode(iv).decode("ascii"),
        "hid": 420,
        "env": env,
        "reg": reg,
        "ts": timestamp,
    }
