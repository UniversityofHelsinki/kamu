from django.contrib.admin.models import LogEntry
from django.contrib.admin.options import ModelAdmin
from django.contrib.admin.views.main import ChangeList
from django.core.exceptions import FieldDoesNotExist
from django.db.models.base import Model
from django.http import HttpRequest
from django.utils import translation
from typing_extensions import TypeVar

from kamu.utils.audit import ActionTypes, AuditLog, CategoryTypes, ModelToCategoryMap

_Model = TypeVar("_Model", bound=Model, covariant=True)

audit_log = AuditLog()


class OrderByNameMixin(ModelAdmin):
    """
    A mixin for Django ModelAdmin that orders by language specific name.
    """

    def get_ordering(cls, request: HttpRequest) -> list[str] | tuple[str, ...]:
        """
        Return the ordering for the admin list view based on current language.
        """
        lang_code = translation.get_language()
        field = "name_" + lang_code
        try:
            cls.model._meta.get_field(field)
            return [field]
        except FieldDoesNotExist:
            return super().get_ordering(request)


class AuditModelAdmin(ModelAdmin):
    """
    A base class for Django ModelAdmin that adds Kamu auditing.
    """

    def get_audit_log_category(self, model: type[_Model]) -> CategoryTypes:
        """
        Return the category for the audit log entries.
        """
        return ModelToCategoryMap.get(model._meta.model_name, "admin") if model._meta.model_name else "admin"

    def kamu_add_audit_log(self, request: HttpRequest, action: ActionTypes, model: type[_Model], obj: object) -> None:
        """
        Add an audit log entry for the given action and object.
        """
        category = self.get_audit_log_category(model)

        def create_message() -> str:
            messages = {
                "list": f"Listed {category}",
                "read": f"Read {category} information",
                "create": f"Created {category}",
                "update": f"Updated {category}",
                "delete": f"Will delete {category}",
            }
            return messages.get(action, f"Performed {action} on {category}")

        identity = getattr(obj, "identity", None)
        objects = [obj]
        if identity:
            objects.append(identity)
        audit_log.info(
            f"Admin: {create_message()}",
            category=category,
            action=action,
            objects=objects,
            outcome="success",
            request=request,
        )

    def get_object(self, request: HttpRequest, object_id: str, from_field: str | None = None) -> object:
        """
        Log that an object has been successfully read.
        """
        obj = super().get_object(request, object_id, from_field)
        if obj:
            queryset = self.get_queryset(request)
            model = queryset.model
            self.kamu_add_audit_log(request, "read", model, obj)
        return obj

    def log_addition(self, request: HttpRequest, obj: type[_Model], message: str) -> LogEntry:
        """
        Log that an object has been successfully added.
        """
        log_entry = super().log_addition(request, obj, message)
        self.kamu_add_audit_log(request, "create", obj, obj)
        return log_entry

    def log_change(self, request: HttpRequest, obj: type[_Model], message: str) -> LogEntry:
        """
        Log that an object has been successfully changed.
        """
        log_entry = super().log_change(request, obj, message)
        self.kamu_add_audit_log(request, "update", obj, obj)
        return log_entry

    def log_deletion(self, request: HttpRequest, obj: type[_Model], object_repr: str) -> LogEntry:
        """
        Log that an object will be deleted.
        """
        log_entry = super().log_deletion(request, obj, object_repr)
        self.kamu_add_audit_log(request, "delete", obj, obj)
        return log_entry

    def get_changelist_instance(self, request: HttpRequest) -> ChangeList:
        """
        Log that object list has been read.
        """
        change_list = super().get_changelist_instance(request)
        if change_list.model:
            self.kamu_add_audit_log(request, "list", change_list.model, None)
        return change_list
