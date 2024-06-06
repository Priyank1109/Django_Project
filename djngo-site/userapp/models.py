from django.db import models
from django.conf import settings

# from django.core.validators import RegexValidator

class UserProfile(models.Model):
    username = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    contact_number = models.CharField(max_length=10, null=True)
    auth_token = models.CharField(max_length=100, null=True)
    is_verified = models.BooleanField(default=False, null=True)
    dt_created_at = models.DateTimeField(auto_now=True, null=True)
    