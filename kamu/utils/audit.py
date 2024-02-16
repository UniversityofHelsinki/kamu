"""
Audit logging
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal, Sequence

from django.conf import settings
from django.contrib.admin.models import ADDITION, CHANGE, DELETION, LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.contenttypes.models import ContentType

from kamu.models.identity import Identity

if TYPE_CHECKING:
    from django.contrib.auth.backends import ModelBackend
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.http import HttpRequest

    from kamu.backends import LocalBaseBackend

UserModel = get_user_model()
logger = logging.getLogger(__name__)
logger_audit = logging.getLogger("audit")


CategoryTypes = Literal[
    "authentication",
    "contact",
    "contract",
    "email_address",
    "group",
    "identifier",
    "identity",
    "membership",
    "phone_number",
    "registration",
    "role",
    "user",
]

ActionTypes = Literal[
    "create",
    "delete",
    "info",
    "link",
    "login",
    "logout",
    "read",
    "unlink",
    "update",
    "search",
]

OutcomeTypes = Literal[
    "failure",
    "success",
    "none",
]


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

    def _get_identity(self, identity: Identity | None, user: AbstractBaseUser | None) -> Identity | None:
        """
        Get identity from identity or linked user.
        """
        if identity:
            return identity
        if user and user.is_authenticated and hasattr(user, "identity"):
            return user.identity
        return None

    def _add_to_admin_log(
        self, actor_id: int | str | None, identity: Identity | None, message: str, category: str, action: str
    ) -> None:
        """
        Create a log entry for add or change messages, if actor and identity are given.
        """
        if not actor_id or not identity or not isinstance(actor_id, int):
            return None
        if category == "identity" and action == "create":
            action_flag = ADDITION
        elif category == "identity" and action == "delete":
            action_flag = DELETION
        else:
            action_flag = CHANGE
        LogEntry.objects.log_action(
            user_id=actor_id,
            content_type_id=ContentType.objects.get_for_model(identity).pk,
            object_id=identity.pk,
            object_repr=str(identity),
            action_flag=action_flag,
            change_message=message,
        )

    def _log(
        self,
        level: int,
        message: str,
        category: CategoryTypes,
        action: ActionTypes,
        outcome: OutcomeTypes = "none",
        request: HttpRequest | None = None,
        backend: type[ModelBackend] | LocalBaseBackend | str | None = None,
        objects: Sequence[object] = (),
        extra: dict[str, str | int | None] | None = None,
        log_to_db: bool = False,
        db_message: Any = None,
    ) -> None:
        """
        Add entry to audit log.

        - message should be a short description of the event.
        - category is a high-level category of the event, like authentication, user or identity.
        - action is a more specific action, like login or create.
        - outcome is the result of the action, like success or failure.
        - objects are linked objects, like user, identity or membership.
        - extra is a dict of additional parameters.

        Logs warning if category, action or outcome are not in the type lists.

        Additional information, like actor user and IP address are parsed from the request, if given.

        Other parameters are linked objects. If given, certain fields like id and name are parsed from them.

        Optionally log message also to Identity admin log if actor and identity can be parsed.
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
        if log_to_db:
            identity = self._get_identity(identity, user)
            if db_message:
                message = db_message
            self._add_to_admin_log(params.get("actor_id"), identity, message, category, action)

    def info(
        self,
        message: str,
        category: CategoryTypes,
        action: ActionTypes,
        outcome: OutcomeTypes = "none",
        request: HttpRequest | None = None,
        backend: type[ModelBackend] | LocalBaseBackend | str | None = None,
        objects: Sequence[object] = (),
        extra: dict[str, str | int | None] | None = None,
        log_to_db: bool = False,
        db_message: Any = None,
    ) -> None:
        """
        Add info entry to audit log.

        Check _log method for parameters.
        """
        self._log(
            level=logging.INFO,
            message=message,
            category=category,
            action=action,
            outcome=outcome,
            request=request,
            backend=backend,
            objects=objects,
            extra=extra,
            log_to_db=log_to_db,
            db_message=db_message,
        )

    def debug(
        self,
        message: str,
        category: CategoryTypes,
        action: ActionTypes,
        outcome: OutcomeTypes = "none",
        request: HttpRequest | None = None,
        backend: type[ModelBackend] | LocalBaseBackend | str | None = None,
        objects: Sequence[object] = (),
        extra: dict[str, str | int | None] | None = None,
        log_to_db: bool = False,
        db_message: Any = None,
    ) -> None:
        """
        Add debug entry to audit log.

        Check _log method for parameters.
        """
        self._log(
            level=logging.DEBUG,
            message=message,
            category=category,
            action=action,
            outcome=outcome,
            request=request,
            backend=backend,
            objects=objects,
            extra=extra,
            log_to_db=log_to_db,
            db_message=db_message,
        )

    def warning(
        self,
        message: str,
        category: CategoryTypes,
        action: ActionTypes,
        outcome: OutcomeTypes = "none",
        request: HttpRequest | None = None,
        backend: type[ModelBackend] | LocalBaseBackend | str | None = None,
        objects: Sequence[object] = (),
        extra: dict[str, str | int | None] | None = None,
        log_to_db: bool = False,
        db_message: Any = None,
    ) -> None:
        """
        Add warning entry to audit log.

        Check _log method for parameters.
        """
        self._log(
            level=logging.WARNING,
            message=message,
            category=category,
            action=action,
            outcome=outcome,
            request=request,
            backend=backend,
            objects=objects,
            extra=extra,
            log_to_db=log_to_db,
            db_message=db_message,
        )
