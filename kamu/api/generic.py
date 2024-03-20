"""
Custom API classes for Kamu
"""

import json
from typing import Any, TypeVar

from django.db.models import Model
from rest_framework import permissions, viewsets
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer

from kamu.utils.audit import AuditLog

audit_log = AuditLog()

_MT = TypeVar("_MT", bound=Model)


class CustomDjangoModelPermissions(permissions.DjangoModelPermissions):
    """
    Custom DjangoModelPermissions class for Kamu. Default DjangoModelPermissions
    doesn't restrict view access. It'll be changed in the next major DRF release.
    DRF PR #8009
    """

    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": ["%(app_label)s.view_%(model_name)s"],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }


class AuditLogReadModelViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Custom ModelViewSet to add audit logging for get actions
    """

    def get_actor(self) -> dict[str, str | int | None] | None:
        if self.request.user and self.request.user.is_authenticated:
            return {"actor": self.request.user.username, "actor_id": self.request.user.pk}
        return None

    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        response = super().list(request, *args, **kwargs)
        extra = self.get_actor() or {}
        extra.update({"search_terms": json.dumps(request.GET.dict())})
        audit_log.info(
            message="API list",
            category=audit_log.get_category_type(self.get_queryset().model),
            action="search",
            outcome="success",
            extra=extra,
        )
        return response

    def retrieve(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        response = super().retrieve(request, *args, **kwargs)
        obj = self.get_object()
        audit_log.info(
            message="API read",
            category=audit_log.get_category_type(obj.__class__),
            action="read",
            outcome="success",
            objects=[obj],
            extra=self.get_actor(),
        )
        return response


class AuditLogModelViewSet(AuditLogReadModelViewSet, viewsets.ModelViewSet):
    """
    Custom ModelViewSet to add audit logging for post actions
    """

    def perform_create(self, serializer: BaseSerializer[_MT]) -> None:
        instance = serializer.save()
        audit_log.info(
            message="API create",
            category=audit_log.get_category_type(instance.__class__),
            action="create",
            outcome="success",
            objects=[instance],
            extra=self.get_actor(),
        )

    def perform_update(self, serializer: BaseSerializer[_MT]) -> None:
        instance = serializer.save()
        audit_log.info(
            message="API update",
            category=audit_log.get_category_type(instance.__class__),
            action="update",
            outcome="success",
            objects=[instance],
            extra=self.get_actor(),
        )

    def perform_destroy(self, instance: _MT) -> None:
        audit_log.info(
            message="API delete",
            category=audit_log.get_category_type(instance.__class__),
            action="delete",
            outcome="success",
            objects=[instance],
            extra=self.get_actor(),
        )
        instance.delete()
