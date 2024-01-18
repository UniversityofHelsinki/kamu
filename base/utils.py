"""
Helper functions
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group

from identity.models import Identity

if TYPE_CHECKING:
    from django.contrib.auth.backends import ModelBackend
    from django.http import HttpRequest

    from base.auth import LocalBaseBackend

UserModel = get_user_model()
logger_audit = logging.getLogger("audit")


def get_client_ip(request: HttpRequest) -> str | None:
    """
    Get client IP address from request.
    """
    check_header = getattr(settings, "HTTP_CHECK_FORWARDING_HEADER", True)
    forwarding_header = getattr(settings, "HTTP_FORWARDING_HEADER", "HTTP_X_FORWARDED_FOR")
    x_forwarded_for = request.META.get(forwarding_header)
    if check_header and x_forwarded_for:
        forwarding_order = getattr(settings, "HTTP_FORWARDING_IP_FIRST", True)
        if forwarding_order:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = x_forwarded_for.split(",")[-1]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip.strip() if ip else None


class AuditLog:
    """
    Audit log helper class.

    This is used in similar way as Python's logging module, giving
    info, debug and warn methods for logging events.
    """

    def log_values_group(self, group: Group) -> dict[str, str | int]:
        """
        Return group's values for audit log.
        """
        return {
            "group_id": group.pk,
            "group": group.name,
        }

    def log_values_user(self, user: AbstractBaseUser) -> dict[str, str | int]:
        """
        Return user's values for audit log.
        """
        return {
            "user_id": user.pk,
            "user": user.get_username(),
        }

    def _parse_identity_and_user_attributes(
        self, identity: Identity | None, user: AbstractBaseUser | None
    ) -> dict[str, Any]:
        """
        If identity or user is missing from the parameters, try to parse them from the other one.
        """
        entry: dict[str, Any] = {}
        if identity and not user:
            if hasattr(identity, "user") and identity.user:
                entry.update(self.log_values_user(identity.user))
        if user and not identity:
            if hasattr(user, "identity") and user.identity:
                entry.update(user.identity.log_values())
        return entry

    def _parse_request(self, request: HttpRequest | None) -> dict[str, Any]:
        """
        Parse attributes from the request.
        """
        entry: dict[str, Any] = {}
        if request:
            entry["ip"] = get_client_ip(request)
            entry["user_agent"] = request.META.get("HTTP_USER_AGENT")
            if request.user and request.user.is_authenticated:
                entry["actor"] = request.user.username
                entry["actor_id"] = request.user.pk
        return entry

    def _log(
        self,
        level: int,
        message: str,
        category: str = "",
        action: str = "",
        outcome: str = "",
        request: HttpRequest | None = None,
        backend: type[ModelBackend] | LocalBaseBackend | str | None = None,
        objects: tuple[object] | tuple[()] = (),
        extra: dict[str, str | int | None] | None = None,
    ) -> None:
        """
        Add entry to audit log.

        - message should be a short description of the event.
        - category is a high-level category of the event, like authentication, user or identity.
        - action is a more specific action, like login or create.
        - outcome is the result of the action, like success or failure.
        - objects are linked objects, like user, identity or membership.
        - extra is a dict of additional parameters.

        Please add new values to the docstring below.

        category values:
        - authentication
        - models in the app like user, identity, membership etc.

        action values:
        - create
        - read
        - update
        - delete
        - link (identity to user, membership to identity etc.)
        - unlink
        - login
        - logout
        - info (generic messages, mostly used in debug logging)

        outcome is the result of the action:
        - success
        - failure
        - not found

        Additional information, like actor user and IP address are parsed from the request, if given.

        Other parameters are linked objects. If given, certain fields like id and name are parsed from them.
        """
        params: dict[str, str | int | None] = {
            "category": category,
            "action": action,
            "outcome": outcome,
        }
        params.update(self._parse_request(request))

        if backend:
            params["backend"] = str(backend)

        user, identity = None, None
        for obj in objects:
            if type(obj) is Group:
                params.update(self.log_values_group(obj))
            elif type(obj) is UserModel and obj:
                user = obj
                params.update(self.log_values_user(obj))
            elif obj and hasattr(obj, "log_values"):
                if type(obj) is Identity:
                    identity = obj
                params.update(obj.log_values())
        params.update(self._parse_identity_and_user_attributes(identity, user))
        if extra:
            params.update(extra)
        logger_audit.log(level, message, extra=params)

    def info(self, message: str, **kwargs: Any) -> None:
        """
        Add info entry to audit log.

        Check _log method for parameters.
        """
        self._log(level=logging.INFO, message=message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        """
        Add debug entry to audit log.

        Check _log method for parameters.
        """
        self._log(level=logging.DEBUG, message=message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """
        Add warning entry to audit log.

        Check _log method for parameters.
        """
        self._log(level=logging.WARNING, message=message, **kwargs)
