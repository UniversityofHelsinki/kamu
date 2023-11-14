"""
Base views, shared between apps.
"""

import logging

from django.conf import settings
from django.contrib.auth import login as auth_login
from django.contrib.auth.views import LoginView
from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views import View

from base.auth import ShibbolethBackend
from base.forms import EmailPhoneForm, LoginForm

logger = logging.getLogger(__name__)


class ShibbolethLoginView(View):
    """
    LoginView to authenticate user with Shibboleth

    TODO: Fix log messages to correct format when it's decided
    """

    def get(self, request, *args, **kwargs):
        redirect_to = request.GET.get("next", settings.LOGIN_REDIRECT_URL)
        backend = ShibbolethBackend()
        user = backend.authenticate(request, create_user=True)
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
            auth_login(request, user, backend="base.auth.ShibbolethBackend")
            return HttpResponseRedirect(redirect_to)
        else:
            logger.debug("Failed Shibboleth login")
        return HttpResponseRedirect(reverse("login"))


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
