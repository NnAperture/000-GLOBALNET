# Example:
# pip install requests cryptography
# python devices/client.py register --server http://127.0.0.1:8000 --name "My PC" --enrollment-token TOKEN
# python devices/client.py verify --server http://127.0.0.1:8000
import argparse, base64, json, os
from pathlib import Path
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_PATH = Path(__file__).with_name("device_private_key.pem")
DEVICE_PATH = Path(__file__).with_name("device.json")

def load_or_create_key():
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    KEY_PATH.write_bytes(pem)
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    return key

def post(server, path, payload):
    response = requests.post(server.rstrip("/") + path, json=payload, timeout=15)
    try:
        body = response.json()
    except ValueError:
        raise SystemExit(f"Server returned non-JSON response: HTTP {response.status_code}")
    if not response.ok:
        raise SystemExit(f"HTTP {response.status_code}: {body}")
    return body

def register(args):
    key = load_or_create_key()
    public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    result = post(args.server, "/api/register/", {"name": args.name, "public_key": public_pem, "enrollment_token": args.enrollment_token})
    DEVICE_PATH.write_text(json.dumps({"device_id": result["device_id"], "fingerprint": result["fingerprint"]}, indent=2))
    print(json.dumps(result, indent=2, ensure_ascii=False))

def verify(args):
    if not KEY_PATH.exists() or not DEVICE_PATH.exists():
        raise SystemExit("Device not enrolled. Run register first.")
    key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    device = json.loads(DEVICE_PATH.read_text())
    challenge = post(args.server, "/api/challenge/", {"device_id": device["device_id"]})
    signature = key.sign(challenge["message_to_sign"].encode())
    result = post(args.server, "/api/verify/", {"challenge_id": challenge["challenge_id"], "signature": base64.b64encode(signature).decode()})
    print(json.dumps(result, indent=2, ensure_ascii=False))

def main():
    parser = argparse.ArgumentParser(description="Django device authentication client")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("register")
    p.add_argument("--server", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--enrollment-token", required=True)
    p.set_defaults(func=register)
    p = sub.add_parser("verify")
    p.add_argument("--server", required=True)
    p.set_defaults(func=verify)
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
