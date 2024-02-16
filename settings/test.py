"""
Test configuration for Kamu service.

Uses local_settings_example configuration with SQLite database, and disables browser security features.
"""

# mypy: disable-error-code="no-redef"
from typing import Any, Sequence

from settings.common import *
from settings.local_settings_example import *

DEBUG: bool = True

SESSION_COOKIE_SECURE: bool = False
CSRF_COOKIE_SECURE: bool = False
SESSION_EXPIRE_AT_BROWSER_CLOSE: bool = False

DATABASES: dict[str, dict[str, Any]] = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}
}
LOGGING["loggers"]["django.request"] = {"level": "ERROR"}
LOGGING["loggers"]["audit"] = {"level": "WARNING"}

# Enable all login backends for testing
AUTHENTICATION_BACKENDS: Sequence[str] = (
    "django.contrib.auth.backends.ModelBackend",
    "kamu.auth.ShibbolethLocalBackend",
    "kamu.auth.ShibbolethEdugainBackend",
    "kamu.auth.ShibbolethHakaBackend",
    "kamu.auth.GoogleBackend",
    "kamu.auth.MicrosoftBackend",
    "kamu.auth.SuomiFiBackend",
    "kamu.auth.EmailSMSBackend",
)