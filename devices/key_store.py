
import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


def get_devices():
    raw = os.environ.get("DEVICE_KEYS", "{}")

    try:
        devices = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("Invalid DEVICE_KEYS JSON")

    if not isinstance(devices, dict):
        raise RuntimeError("DEVICE_KEYS must be a JSON object")

    return devices


def get_public_key(device_id):
    devices = get_devices()

    device = devices.get(str(device_id))

    if not isinstance(device, dict):
        return None

    if device.get("active") is not True:
        return None

    encoded = device.get("public_key")

    if not isinstance(encoded, str):
        return None

    try:
        public_bytes = base64.b64decode(
            encoded,
            validate=True
        )

        if len(public_bytes) != 32:
            return None

        return Ed25519PublicKey.from_public_bytes(
            public_bytes
        )

    except Exception:
        return None


def get_fingerprint(public_key_bytes):
    return hashlib.sha256(
        public_key_bytes
    ).hexdigest()
