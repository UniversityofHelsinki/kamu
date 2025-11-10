from typing import Any
from uuid import UUID

from django.db import models


class Char32UUIDField(models.UUIDField):
    """
    Use CHAR(32) to store UUID values to fix storing UUID in MariaDB 10.7+.
    """

    def db_type(self, connection: Any) -> Any:
        return "char(32)"

    def get_db_prep_value(self, value: Any, connection: Any, prepared: bool = False) -> Any:
        value = super().get_db_prep_value(value, connection, prepared)
        if isinstance(value, UUID) and value is not None:
            value = value.hex
        return value
