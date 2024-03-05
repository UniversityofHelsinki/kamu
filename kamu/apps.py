from django.apps import AppConfig


class BaseConfig(AppConfig):
    name = "kamu"
    verbose_name = "Kamu service"

    def ready(self) -> None:
        from . import signals  # noqa: F401
