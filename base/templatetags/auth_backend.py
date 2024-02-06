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
        "local": "base.auth.ShibbolethLocalBackend",
        "haka": "base.auth.ShibbolethHakaBackend",
        "edugain": "base.auth.ShibbolethEdugainBackend",
        "google": "base.auth.GoogleBackend",
        "microsoft": "base.auth.MicrosoftBackend",
        "suomifi": "base.auth.SuomiFiBackend",
        "emailsms": "base.auth.EmailSMSBackend",
    }
    backend = backends.get(value)
    if backend and backend in settings.AUTHENTICATION_BACKENDS:
        return True
    return False
