import base64, hashlib, json
from django.test import TestCase, Client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .models import Device

class DeviceAuthTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key()
        pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.device = Device.objects.create(name="test", public_key=pem, public_key_fingerprint=hashlib.sha256(raw).hexdigest())

    def test_challenge_verified_once(self):
        r = self.client.post("/api/challenge/", data=json.dumps({"device_id": self.device.pk}), content_type="application/json")
        c = r.json()
        sig = base64.b64encode(self.private.sign(c["message_to_sign"].encode())).decode()
        body = json.dumps({"challenge_id": c["challenge_id"], "signature": sig})
        ok = self.client.post("/api/verify/", data=body, content_type="application/json")
        self.assertEqual(ok.status_code, 200)
        replay = self.client.post("/api/verify/", data=body, content_type="application/json")
        self.assertEqual(replay.status_code, 403)

    def test_wrong_signature_rejected(self):
        r = self.client.post("/api/challenge/", data=json.dumps({"device_id": self.device.pk}), content_type="application/json")
        c = r.json()
        other = Ed25519PrivateKey.generate()
        sig = base64.b64encode(other.sign(c["message_to_sign"].encode())).decode()
        result = self.client.post("/api/verify/", data=json.dumps({"challenge_id": c["challenge_id"], "signature": sig}), content_type="application/json")
        self.assertEqual(result.status_code, 403)
