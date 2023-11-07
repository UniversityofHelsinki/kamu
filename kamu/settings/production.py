# Generic production settings for kamu project.
# Requires local_settings.py, check local_settings_example.py for more information.

from kamu.settings.common import *

DEBUG = False

try:
    from .local_logging import *
except ModuleNotFoundError:
    from .logging import *

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

try:
    from kamu.settings.local_settings import *
except ModuleNotFoundError:
    print("No kamu/settings/local_settings.py found, exiting.")
