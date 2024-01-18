"""
Python logging configuration in dictConfig format.

Production config uses local_logging.py for logging configuration if available. Otherwise, logging.py is used.

See https://docs.djangoproject.com/en/dev/topics/logging/ for more information.
"""

import os

LOGGING: dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "text": {
            "format": "%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        },
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "text",
        },
        "json": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
        #        'json': {
        #            'class': 'logging.FileHandler',
        #            'filename': 'production.log',
        #            'formatter': 'json',
        #        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
        "audit": {
            "handlers": ["json"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
