import base64, hashlib, json, secrets
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from .models import Challenge, Device, EnrollmentToken

MAX_BODY = 16384
def read_json(request):
    if len(request.body) > MAX_BODY:
        raise ValueError("Request body is too large")
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Expected valid JSON")
    if not isinstance(data, dict):
        raise ValueError("JSON object expected")
    return data
def error(message, status=400):
    return JsonResponse({"ok": False, "error": message}, status=status)

@require_GET
def health(request):
    return JsonResponse({"ok": True, "service": "device-auth"})

@csrf_exempt
@require_POST
def register_device(request):
    try:
        data = read_json(request)
        name = str(data.get("name", "")).strip()
        pem = str(data.get("public_key", "")).strip()
        raw_token = str(data.get("enrollment_token", "")).strip()
        if not name or len(name) > 120:
            return error("name is required (max 120 characters)")
        if not raw_token or not pem or len(pem) > 4096:
            return error("public_key and enrollment_token are required")
        try:
            key = serialization.load_pem_public_key(pem.encode())
            if not isinstance(key, Ed25519PublicKey):
                return error("Only Ed25519 public keys are accepted")
        except (ValueError, TypeError):
            return error("Invalid Ed25519 PEM public key")
        raw_key = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        fingerprint = hashlib.sha256(raw_key).hexdigest()
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with transaction.atomic():
            token = EnrollmentToken.objects.select_for_update().filter(token_hash=token_hash).first()
            if token is None or not token.is_usable:
                return error("Invalid, expired, or already-used enrollment token", 403)
            if Device.objects.filter(public_key_fingerprint=fingerprint).exists():
                return error("This public key is already registered", 409)
            device = Device.objects.create(name=name, public_key=pem, public_key_fingerprint=fingerprint)
            token.used_at = timezone.now()
            token.save(update_fields=["used_at"])
        return JsonResponse({"ok": True, "device_id": device.pk, "fingerprint": fingerprint}, status=201)
    except ValueError as exc:
        return error(str(exc))

@csrf_exempt
@require_POST
def create_challenge(request):
    try:
        data = read_json(request)
        device_id = data.get("device_id")
        if not isinstance(device_id, int) or isinstance(device_id, bool):
            return error("device_id must be an integer")
        device = Device.objects.filter(pk=device_id, is_active=True).first()
        if device is None:
            return error("Unknown or inactive device", 403)
        nonce = secrets.token_urlsafe(32)
        challenge = Challenge.objects.create(device=device, nonce=nonce, expires_at=timezone.now() + Challenge.lifetime())
        message = f"device-auth:v1:{device.pk}:{challenge.pk}:{nonce}"
        return JsonResponse({"ok": True, "challenge_id": challenge.pk, "nonce": nonce, "expires_at": challenge.expires_at.isoformat(), "message_to_sign": message})
    except ValueError as exc:
        return error(str(exc))

@csrf_exempt
@require_POST
def verify_challenge(request):
    try:
        data = read_json(request)
        challenge_id = data.get("challenge_id")
        sig_text = str(data.get("signature", ""))
        if not isinstance(challenge_id, int) or isinstance(challenge_id, bool) or not sig_text:
            return error("challenge_id and signature are required")
        try:
            signature = base64.b64decode(sig_text, validate=True)
        except (ValueError, TypeError):
            return error("signature must be valid base64")
        with transaction.atomic():
            challenge = Challenge.objects.select_for_update().select_related("device").filter(pk=challenge_id).first()
            if challenge is None or not challenge.is_usable:
                return error("Challenge not found, expired, or already used", 403)
            device = challenge.device
            if not device.is_active:
                return error("Device is inactive", 403)
            message = f"device-auth:v1:{device.pk}:{challenge.pk}:{challenge.nonce}".encode()
            try:
                key = serialization.load_pem_public_key(device.public_key.encode())
                if not isinstance(key, Ed25519PublicKey):
                    return error("Stored public key is invalid", 500)
                key.verify(signature, message)
            except InvalidSignature:
                return error("Invalid signature", 403)
            except (ValueError, TypeError):
                return error("Stored public key is invalid", 500)
            now = timezone.now()
            challenge.used_at = now
            challenge.save(update_fields=["used_at"])
            device.last_verified_at = now
            device.save(update_fields=["last_verified_at"])
        return JsonResponse({"ok": True, "verified": True, "device_id": device.pk})
    except ValueError as exc:
        return error(str(exc))
