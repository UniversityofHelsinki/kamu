from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views import View

from identity.models import Identity


class FrontPageView(View):
    template_name = "front.html"

    def get(self, request):
        return render(request, self.template_name)


class IdentityView(LoginRequiredMixin, View):
    template_name = "identity.html"

    def get(self, request):
        """
        Renders user identity information.
        Creates an identity for user if identity does not exist.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if not user:
            identity = None
        else:
            try:
                identity = Identity.objects.get(user=user)
            except Identity.DoesNotExist:
                identity = Identity.objects.create(user=user)
                messages.add_message(request, messages.WARNING, _("New identity created."))
        return render(request, self.template_name, {"object": identity})
