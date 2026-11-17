import hashlib, secrets
from django.contrib import admin, messages
from django.utils import timezone
from .models import Device, EnrollmentToken, Challenge

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "public_key_fingerprint", "is_active", "created_at", "last_verified_at")
    list_filter = ("is_active",)
    search_fields = ("name", "public_key_fingerprint")
    readonly_fields = ("public_key", "public_key_fingerprint", "created_at", "last_verified_at")
    actions = ("activate_devices", "deactivate_devices")
    @admin.action(description="Активировать выбранные устройства")
    def activate_devices(self, request, queryset):
        queryset.update(is_active=True)
    @admin.action(description="Заблокировать выбранные устройства")
    def deactivate_devices(self, request, queryset):
        queryset.update(is_active=False)

@admin.register(EnrollmentToken)
class EnrollmentTokenAdmin(admin.ModelAdmin):
    list_display = ("label", "created_at", "expires_at", "used_at")
    readonly_fields = ("token_hash", "created_at", "used_at")
    fields = ("label", "expires_at", "token_hash", "created_at", "used_at")
    def save_model(self, request, obj, form, change):
        if not change and not obj.token_hash:
            raw = secrets.token_urlsafe(32)
            obj.token_hash = hashlib.sha256(raw.encode()).hexdigest()
            obj._raw_token_once = raw
        super().save_model(request, obj, form, change)
        if hasattr(obj, "_raw_token_once"):
            self.message_user(request, f"Скопируйте код сейчас — повторно он не показывается: {obj._raw_token_once}", level=messages.WARNING)

@admin.register(Challenge)
class ChallengeAdmin(admin.ModelAdmin):
    list_display = ("device", "created_at", "expires_at", "used_at")
    readonly_fields = ("device", "nonce", "created_at", "expires_at", "used_at")
    def has_add_permission(self, request):
        return False
