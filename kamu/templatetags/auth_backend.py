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
        "local": "kamu.backends.ShibbolethLocalBackend",
        "haka": "kamu.backends.ShibbolethHakaBackend",
        "edugain": "kamu.backends.ShibbolethEdugainBackend",
        "google": "kamu.backends.GoogleBackend",
        "microsoft": "kamu.backends.MicrosoftBackend",
        "suomifi": "kamu.backends.SuomiFiBackend",
        "emailsms": "kamu.backends.EmailSMSBackend",
    }
    backend = backends.get(value)
    if backend and backend in settings.AUTHENTICATION_BACKENDS:
        return True
    return False
