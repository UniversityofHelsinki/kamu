from django.apps import AppConfig


class BaseConfig(AppConfig):
    name = "base"
    verbose_name = "Base app for Kamu service"

    def ready(self) -> None:
        from . import signals
