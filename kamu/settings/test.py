"""
Test configuration for Kamu service.

Uses local_settings_example configuration with SQLite database, and disables browser security features.
"""

from kamu.settings.common import *
from kamu.settings.local_settings_example import *

DEBUG = True

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",  # type: ignore[dict-item]
    }
}
