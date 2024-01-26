"""
Generic production settings for Kamu service.

Requires local_settings.py, check local_settings_example.py for more information.
"""

# mypy: disable-error-code="no-redef"

from kamu.settings.common import *

DEBUG: bool = False

try:
    from .local_logging import *
except ModuleNotFoundError:
    from .logging import *

SESSION_COOKIE_SECURE: bool = True
SESSION_COOKIE_HTTPONLY: bool = True
CSRF_COOKIE_SECURE: bool = True
CSRF_COOKIE_HTTPONLY: bool = True
SESSION_EXPIRE_AT_BROWSER_CLOSE: bool = True

try:
    from kamu.settings.local_settings import *
except ModuleNotFoundError:
    print("No kamu/settings/local_settings.py found, exiting.")
