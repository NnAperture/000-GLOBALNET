
import base64
import json
import secrets
import uuid

from cryptography.exceptions import InvalidSignature

from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .key_store import get_public_key


CHALLENGE_TTL = 120
MAX_BODY = 8192


def read_json(request):
    if len(request.body) > MAX_BODY:
        raise ValueError("Request too large")

    try:
        data = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid JSON")

    if not isinstance(data, dict):
        raise ValueError("JSON object expected")

    return data


def error(message, status=400):
    return JsonResponse(
        {"ok": False, "error": message},
        status=status
    )


@require_GET
def health(request):
    return JsonResponse({
        "ok": True,
        "service": "device-auth",
        "database": False
    })


@csrf_exempt
@require_POST
def create_challenge(request):
    try:
        data = read_json(request)

        device_id = data.get("device_id")

        if not isinstance(device_id, str) or not device_id:
            return error("Invalid device_id")

        if get_public_key(device_id) is None:
            return error("Unknown or inactive device", 403)

        challenge_id = uuid.uuid4().hex
        nonce = secrets.token_urlsafe(32)

        message = (
            f"device-auth:v1:"
            f"{device_id}:"
            f"{challenge_id}:"
            f"{nonce}"
        )

        cache.set(
            f"challenge:{challenge_id}",
            {
                "device_id": device_id,
                "message": message,
            },
            timeout=CHALLENGE_TTL
        )

        return JsonResponse({
            "ok": True,
            "device_id": device_id,
            "challenge_id": challenge_id,
            "message_to_sign": message,
            "expires_in": CHALLENGE_TTL,
        })

    except ValueError as exc:
        return error(str(exc))

    except RuntimeError:
        return error("Invalid server configuration", 500)


@csrf_exempt
@require_POST
def verify_challenge(request):
    try:
        data = read_json(request)

        challenge_id = data.get("challenge_id")
        signature_text = data.get("signature")

        if not isinstance(challenge_id, str):
            return error("Invalid challenge_id")

        if not isinstance(signature_text, str):
            return error("Invalid signature")

        challenge_key = f"challenge:{challenge_id}"

        challenge = cache.get(challenge_key)

        if challenge is None:
            return error(
                "Challenge expired or already used",
                403
            )

        try:
            signature = base64.b64decode(
                signature_text,
                validate=True
            )
        except Exception:
            return error("Invalid base64 signature")

        device_id = challenge["device_id"]

        try:
            public_key = get_public_key(device_id)
        except RuntimeError:
            return error("Invalid server configuration", 500)

        if public_key is None:
            return error("Device inactive", 403)

        try:
            public_key.verify(
                signature,
                challenge["message"].encode("utf-8")
            )
        except InvalidSignature:
            return error("Invalid signature", 403)

        # Одноразовое использование challenge
        used_key = f"used:{challenge_id}"

        if not cache.add(
            used_key,
            True,
            timeout=CHALLENGE_TTL
        ):
            return error("Challenge already used", 403)

        cache.delete(challenge_key)

        return JsonResponse({
            "ok": True,
            "verified": True,
            "device_id": device_id
        })

    except ValueError as exc:
        return error(str(exc))
