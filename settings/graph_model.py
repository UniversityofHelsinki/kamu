"""
Configuration for creating Database Graph.

Users test settings and adds django_extensions to INSTALLED_APPS
"""

from settings.test import *

INSTALLED_APPS += ["django_extensions"]
