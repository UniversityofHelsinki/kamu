"""
Base views, shared between apps.
"""

import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User as UserType
from django.contrib.auth.views import LoginView
from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views import View

from base.auth import GoogleBackend, ShibbolethBackend
from base.forms import EmailPhoneForm, LoginForm

logger = logging.getLogger(__name__)


class RemoteLoginView(View):
    """
    Base class for remote login views. Overwrite _authenticate_backend and _auth_login methods with
    correct backend settings.
    """

    @staticmethod
    def _authenticate_backend(request) -> None | UserType:
        """
        Authentication user against a backend.
        # backend = ShibbolethBackend()
        # user = backend.authenticate(request, create_user=True)
        # return user
        """
        return None

    @staticmethod
    def _remote_auth_login(request, user) -> None:
        """
        Log user in using a correct backend.

        # auth_login(request, user, backend="base.auth.ShibbolethBackend")
        """
        pass

    def get(self, request, *args, **kwargs):
        redirect_to = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
        user = self._authenticate_backend(request)
        if user:
            if not user.is_active:
                info_message = _("This account is inactive.")
                logger.warning(f"User {user} with inactive account tried to log in")
                return render(request, "info.html", {"message": info_message})
            if redirect_to == request.path:
                error_message = _("Redirection loop for authenticated user detected. Please contact service admins.")
                logger.error(
                    "Redirection loop detected in user authentication. Check that your LOGIN_REDIRECT_URL doesn't "
                    "point to the login page."
                )
                return render(request, "error.html", {"message": error_message})
            self._remote_auth_login(request, user)
            return HttpResponseRedirect(redirect_to)
        else:
            messages.error(request, _("Login failed."))
            logger.debug("Failed login")
        return HttpResponseRedirect(reverse("login"))


class ShibbolethLoginView(RemoteLoginView):
    """
    LoginView to authenticate user with Shibboleth
    """

    @staticmethod
    def _authenticate_backend(request):
        backend = ShibbolethBackend()
        user = backend.authenticate(request, create_user=True)
        return user

    @staticmethod
    def _remote_auth_login(request, user):
        auth_login(request, user, backend="base.auth.ShibbolethBackend")


class GoogleLoginView(RemoteLoginView):
    """
    LoginView to authenticate user with Google
    """

    @staticmethod
    def _authenticate_backend(request):
        backend = GoogleBackend()
        user = backend.authenticate(request, create_user=True)
        return user

    @staticmethod
    def _remote_auth_login(request, user):
        auth_login(request, user, backend="base.auth.GoogleBackend")


class EmailPhoneLoginView(LoginView):
    """
    LoginView to authenticate user with email address and phone number.

    TODO: Currently for testing purposes. It needs verification methods etc.
    """

    form_class = EmailPhoneForm
    template_name = "login_email.html"

    def form_valid(self, form):
        """Security check complete. Log the user in."""
        auth_login(self.request, form.get_user(), backend="base.auth.EmailSMSBackend")
        return HttpResponseRedirect(self.get_success_url())


class LocalLoginView(LoginView):
    """
    LoginView with the custom login form.
    """

    template_name = "login_local.html"
    form_class = LoginForm


class CustomLoginView(View):
    """
    View with login options
    """

    template_name = "login.html"

    def get(self, request):
        return render(request, self.template_name)


class FrontPageView(View):
    """
    Front page view.
    """

    template_name = "front.html"

    def get(self, request):
        return render(request, self.template_name)
