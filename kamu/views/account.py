"""
User account views for the UI.
"""

import string
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import QuerySet
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBase,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import DetailView, FormView, ListView
from django.views.generic.edit import FormMixin

from kamu.connectors import ApiError
from kamu.connectors.account import AccountApiConnector
from kamu.connectors.email import (
    send_account_creation_notification,
    send_account_password_reset_notification,
)
from kamu.forms.account import AccountCreateForm, PasswordResetForm
from kamu.models.account import Account
from kamu.models.identity import Identity
from kamu.models.role import Permission
from kamu.utils.account import get_account_data, get_minimum_password_length
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


class AccountCreateView(LoginRequiredMixin, FormView):
    """
    View to create a user account.
    """

    form_class = AccountCreateForm
    template_name = "account/account_create.html"
    success_url = "#"
    identity: Identity | None = None
    account_type: Account.Type | None = None

    @method_decorator(sensitive_post_parameters("password"))
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Restricts identity to logged-in user unless user has permission to manage all accounts.
        Restricts account types to those that are allowed for the identity and not yet activated.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            self.identity = Identity.objects.get(pk=self.kwargs.get("identity_pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        if self.identity.user != user and not user.has_perms(["kamu.change_accounts"]):
            raise PermissionDenied
        account_permissions = self.identity.get_permissions(permission_type=Permission.Type.ACCOUNT).values_list(
            "identifier", flat=True
        )
        existing_accounts = Account._default_manager.filter(identity=self.identity).values_list("type", flat=True)
        self.account_type = self.kwargs.get("account_type", None)
        if (
            not self.account_type
            or settings.ACCOUNT_ACTIONS.get(self.account_type) != "create"
            or self.account_type not in account_permissions
            or self.account_type in existing_accounts
        ):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add account information to context data
        """
        context = super().get_context_data(**kwargs)
        if not self.identity or not self.account_type:
            raise PermissionDenied
        context["identity"] = self.identity
        context["account_type"] = self.account_type
        context["account_info"] = get_account_data(self.identity, self.account_type)
        context["services"] = self.identity.get_permissions(permission_type=Permission.Type.SERVICE)
        context["min_password_length"] = get_minimum_password_length()
        return context

    def get_alphabetic_characters_from_names(self) -> str:
        """
        Return all alphabetic characters from names.
        """
        if not self.identity:
            return ""
        return "".join(
            sorted(
                set(
                    char
                    for char in (
                        self.identity.given_names
                        + self.identity.surname
                        + self.identity.given_name_display
                        + self.identity.surname_display
                    ).lower()
                )
                & set(string.ascii_lowercase)
            )
        )

    def generate_uids(self, forced: bool = False) -> list[str]:
        """
        Generate user ID choices or return saved choices from the session.

        Exclude 3 digit part from FPIC and all alphabetic characters from names.
        """
        if not forced and self.request.session.get("uid_choices"):
            return self.request.session["uid_choices"]
        exclude_chars = ""
        exclude_string = ""
        if self.identity:
            if self.identity.fpic:
                try:
                    exclude_string = self.identity.fpic[7:10]
                except IndexError:
                    pass
            exclude_chars = self.get_alphabetic_characters_from_names()
        try:
            connector = AccountApiConnector()
            uid_choices = connector.get_uid_choices(
                number=settings.ACCOUNT_API.get("UID_CHOICES_NUMBER", 5),
                exclude_chars=exclude_chars,
                exclude_string=exclude_string,
            )
            self.request.session["uid_choices"] = uid_choices
            return uid_choices
        except ApiError:
            messages.add_message(
                self.request, messages.ERROR, _("Could not load user ID choices, please try again later.")
            )
        return []

    def get_form_kwargs(self) -> dict[str, Any]:
        """
        Add uid choices to form kwargs.
        """
        kwargs = super().get_form_kwargs()
        kwargs["uid_choices"] = self.generate_uids()
        return kwargs

    @method_decorator(sensitive_post_parameters("password"))
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for regeneration.
        """
        if "regenerate_uids" in self.request.POST:
            self.generate_uids(forced=True)
            return HttpResponseRedirect(self.get_success_url())
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form: AccountCreateForm) -> HttpResponse:
        """
        Create user account.
        """
        if not self.identity or not self.account_type:
            raise PermissionDenied
        password = form.cleaned_data["password"]
        uid = form.cleaned_data["uid"]
        if settings.ACCOUNT_ACTIONS.get(self.account_type) == "create":
            try:
                connector = AccountApiConnector()
                account = connector.create_account(
                    identity=self.identity, uid=uid, password=password, account_type=self.account_type
                )
            except ApiError as e:
                audit_log.warning(
                    f"Account of type {self.account_type} creation failed: {e}",
                    category="account",
                    action="create",
                    outcome="failure",
                    request=self.request,
                    objects=[self.identity],
                    log_to_db=False,
                )
                messages.add_message(
                    self.request, messages.ERROR, _("Account creation failed, please try again later.")
                )
                return self.form_invalid(form)
            audit_log.info(
                f"Account created: {account.uid}",
                category="account",
                action="create",
                outcome="success",
                request=self.request,
                objects=[self.identity, account],
                log_to_db=True,
            )
            messages.add_message(self.request, messages.INFO, _("Account created."))
            send_account_creation_notification(account)
            del self.request.session["uid_choices"]
            self.success_url = reverse("identity-detail", kwargs={"pk": self.identity.pk})
            return super().form_valid(form)
        raise PermissionDenied


class AccountListView(LoginRequiredMixin, ListView[Account]):
    """
    List accounts for an identity.
    """

    template_name = "account/account_list.html"
    success_url = "#"
    identity = None

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Restricts identity to logged-in user unless user has permission to view all accounts.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            raise PermissionDenied
        try:
            self.identity = Identity.objects.get(pk=self.kwargs.get("pk"))
        except Identity.DoesNotExist:
            raise PermissionDenied
        if self.identity.user != user and not user.has_perms(["kamu.view_accounts"]):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log listing account information.
        """
        get = super().get(request, *args, **kwargs)
        audit_log.info(
            "Listed account information",
            category="account",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.identity],
        )
        return get

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add identity and the list of creatable accounts to context.
        """
        context = super().get_context_data(**kwargs)
        if not self.identity:
            raise PermissionDenied
        context["identity"] = self.identity
        account_permissions = self.identity.get_permissions(permission_type=Permission.Type.ACCOUNT).values_list(
            "identifier", flat=True
        )
        existing_accounts = self.get_queryset().values_list("type", flat=True)
        creatable_accounts = []
        for account_type in set(account_permissions) - set(existing_accounts):
            if settings.ACCOUNT_ACTIONS.get(account_type):
                creatable_accounts.append(
                    {
                        "type": account_type,
                        "name": Account.Type(account_type).label,
                        "action": settings.ACCOUNT_ACTIONS.get(account_type),
                    }
                )
        context["creatable_accounts"] = creatable_accounts
        return context

    def get_queryset(self) -> QuerySet[Account]:
        """
        List user's accounts.
        """
        queryset = Account._default_manager.filter(identity__pk=self.kwargs.get("pk")).order_by("-status", "type")
        return queryset


class AccountDetailView(LoginRequiredMixin, FormMixin, DetailView[Account]):
    """
    View and manage account information.
    """

    model = Account
    form_class = PasswordResetForm
    template_name = "account/account_detail.html"
    success_url = "#"

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Log viewing account information.
        """
        self.object = self.get_object()
        if self.object:
            if self.object.update_status(request=self.request):
                self.object.refresh_from_db()
            if self.object.status == Account.Status.EXPIRED:
                messages.add_message(self.request, messages.WARNING, _("Your permission to this account has expired."))
        audit_log.info(
            "Read account information",
            category="account",
            action="read",
            outcome="success",
            request=self.request,
            objects=[self.object, self.object.identity],
        )
        get = super().get(request, *args, **kwargs)
        return get

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """
        Add minimum password length to context data
        """
        context = super().get_context_data(**kwargs)
        context["min_password_length"] = get_minimum_password_length()
        return context

    def get_queryset(self) -> QuerySet[Account]:
        """
        Restrict access to user's own information, unless user has permission to view all account information.
        """
        queryset = super().get_queryset()
        if not self.request.user.is_authenticated:
            return queryset.none()
        if not self.request.user.has_perms(["kamu.view_accounts"]):
            return queryset.filter(identity__user=self.request.user)
        return queryset

    def _enable_account(self) -> None:
        """
        Enable account.
        """
        if not self.request.user.is_authenticated:
            raise PermissionDenied
        if not (
            self.request.user.has_perms(["kamu.change_accounts"]) or self.object.identity.user == self.request.user
        ):
            raise PermissionDenied
        if self.object.type not in self.object.identity.get_permissions(
            permission_type=Permission.Type.ACCOUNT
        ).values_list("identifier", flat=True):
            messages.add_message(self.request, messages.WARNING, _("Your permission to this account has expired."))
            return
        if self.object.status == Account.Status.DISABLED:
            try:
                connector = AccountApiConnector()
                connector.enable_account(self.object)
            except ApiError as e:
                audit_log.warning(
                    f"Account enabling failed: {e}",
                    category="account",
                    action="update",
                    outcome="failure",
                    request=self.request,
                    objects=[self.object, self.object.identity],
                    log_to_db=False,
                )
                messages.add_message(
                    self.request, messages.ERROR, _("Account enabling failed, please try again later.")
                )
                return
            audit_log.info(
                f"Account enabled: {self.object.uid}",
                category="account",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity],
                log_to_db=True,
            )
            messages.add_message(self.request, messages.INFO, _("Account enabled."))

    def _disable_account(self) -> None:
        """
        Disables account
        """
        if not self.request.user.is_authenticated:
            raise PermissionDenied
        if not (
            self.request.user.has_perms(["kamu.change_accounts"]) or self.object.identity.user == self.request.user
        ):
            raise PermissionDenied
        if self.object.status == Account.Status.ENABLED:
            try:
                connector = AccountApiConnector()
                connector.disable_account(self.object)
            except ApiError as e:
                audit_log.warning(
                    f"Account disabling failed: {e}",
                    category="account",
                    action="update",
                    outcome="failure",
                    request=self.request,
                    objects=[self.object, self.object.identity],
                    log_to_db=False,
                )
                messages.add_message(
                    self.request, messages.ERROR, _("Account disabling failed, please try again later.")
                )
                return
            audit_log.info(
                f"Account disabled: {self.object.uid}",
                category="account",
                action="update",
                outcome="success",
                request=self.request,
                objects=[self.object, self.object.identity],
                log_to_db=True,
            )
            messages.add_message(self.request, messages.INFO, _("Account disabled."))

    @method_decorator(sensitive_post_parameters("password"))
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """
        Check for account methods.
        """
        if not self.request.user.is_authenticated:
            raise PermissionDenied
        self.object = self.get_object()
        if self.object:
            if self.object.update_status(request=self.request):
                self.object.refresh_from_db()
            if self.object.status == Account.Status.EXPIRED:
                messages.add_message(self.request, messages.WARNING, _("Your permission to this account has expired."))
                return HttpResponseRedirect(self.get_success_url())
        else:
            raise PermissionDenied
        if "enable_account" in self.request.POST:
            self._enable_account()
            return HttpResponseRedirect(self.get_success_url())
        if "disable_account" in self.request.POST:
            self._disable_account()
            return HttpResponseRedirect(self.get_success_url())
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form: PasswordResetForm) -> HttpResponse:
        """
        Reset user password.
        """
        password = form.cleaned_data["password"]
        try:
            connector = AccountApiConnector()
            connector.set_account_password(account=self.object, password=password)
        except ApiError as e:
            audit_log.warning(
                f"Password reset failed: {e}",
                category="account",
                action="update",
                outcome="failure",
                request=self.request,
                objects=[self.object.identity, self.object],
                log_to_db=False,
            )
            messages.add_message(self.request, messages.ERROR, _("Password reset failed, please try again later."))
            return self.form_invalid(form)
        audit_log.info(
            f"Password reset: {self.object.uid}",
            category="account",
            action="update",
            outcome="success",
            request=self.request,
            objects=[self.object.identity, self.object],
            log_to_db=True,
        )
        messages.add_message(self.request, messages.INFO, _("Password reset."))
        send_account_password_reset_notification(self.object)
        self.success_url = reverse("account-detail", kwargs={"pk": self.object.pk})
        return super().form_valid(form)
