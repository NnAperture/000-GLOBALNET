
import argparse
import base64
import hashlib
import json
import os

from pathlib import Path

import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)


KEY_PATH = Path(__file__).with_name(
    "device_private_key.pem"
)

DEVICE_PATH = Path(__file__).with_name(
    "device.json"
)


def setup(args):
    if KEY_PATH.exists():
        key = serialization.load_pem_private_key(
            KEY_PATH.read_bytes(),
            password=None
        )
    else:
        key = Ed25519PrivateKey.generate()

        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        KEY_PATH.write_bytes(pem)

        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass

    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

    public_b64 = base64.b64encode(
        public_bytes
    ).decode("ascii")

    fingerprint = hashlib.sha256(
        public_bytes
    ).hexdigest()

    DEVICE_PATH.write_text(
        json.dumps({
            "device_id": args.device_id,
            "fingerprint": fingerprint
        }, indent=2),
        encoding="utf-8"
    )

    print("\nДобавь в Render → DEVICE_KEYS:\n")

    print(json.dumps({
        args.device_id: {
            "public_key": public_b64,
            "active": True
        }
    }, indent=2))

    print("\nFingerprint:", fingerprint)

    print("\nПриватный ключ сохранён:")
    print(KEY_PATH)

    print("\nНе передавай приватный ключ никому!")


def post(server, path, payload):
    response = requests.post(
        server.rstrip("/") + path,
        json=payload,
        timeout=20
    )

    try:
        body = response.json()
    except ValueError:
        raise SystemExit(
            f"Server error: HTTP {response.status_code}"
        )

    if not response.ok:
        raise SystemExit(
            f"HTTP {response.status_code}: {body}"
        )

    return body


def verify(args):
    if not KEY_PATH.exists() or not DEVICE_PATH.exists():
        raise SystemExit(
            "Сначала выполни команду setup"
        )

    key = serialization.load_pem_private_key(
        KEY_PATH.read_bytes(),
        password=None
    )

    device = json.loads(
        DEVICE_PATH.read_text(encoding="utf-8")
    )

    challenge = post(
        args.server,
        "/api/challenge/",
        {
            "device_id": device["device_id"]
        }
    )

    signature = key.sign(
        challenge["message_to_sign"].encode("utf-8")
    )

    result = post(
        args.server,
        "/api/verify/",
        {
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(
                signature
            ).decode("ascii")
        }
    )

    print(json.dumps(
        result,
        indent=2,
        ensure_ascii=False
    ))


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True
    )

    p = sub.add_parser("setup")
    p.add_argument(
        "--device-id",
        required=True
    )
    p.set_defaults(func=setup)

    p = sub.add_parser("verify")
    p.add_argument(
        "--server",
        required=True
    )
    p.set_defaults(func=verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
