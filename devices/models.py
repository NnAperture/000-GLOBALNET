from datetime import timedelta
from django.db import models
from django.utils import timezone

class EnrollmentToken(models.Model):
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    label = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return self.label or f"Код регистрации #{self.pk}"
    @property
    def is_usable(self):
        return self.used_at is None and self.expires_at > timezone.now()

class Device(models.Model):
    name = models.CharField(max_length=120)
    public_key = models.TextField(unique=True)
    public_key_fingerprint = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return f"{self.name} ({self.public_key_fingerprint[:12]})"

class Challenge(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="challenges")
    nonce = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    @classmethod
    def lifetime(cls):
        return timedelta(minutes=2)
    @property
    def is_usable(self):
        return self.used_at is None and self.expires_at > timezone.now()
