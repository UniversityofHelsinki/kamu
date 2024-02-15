"""
Custom template tag to check if backend is enabled.
"""

from django import template
from django.conf import settings

register = template.Library()


@register.filter
def enabled_backend(value: str) -> bool:
    backends = {
        "password": "django.contrib.auth.backends.ModelBackend",
        "local": "kamu.auth.ShibbolethLocalBackend",
        "haka": "kamu.auth.ShibbolethHakaBackend",
        "edugain": "kamu.auth.ShibbolethEdugainBackend",
        "google": "kamu.auth.GoogleBackend",
        "microsoft": "kamu.auth.MicrosoftBackend",
        "suomifi": "kamu.auth.SuomiFiBackend",
        "emailsms": "kamu.auth.EmailSMSBackend",
    }
    backend = backends.get(value)
    if backend and backend in settings.AUTHENTICATION_BACKENDS:
        return True
    return False
