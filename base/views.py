from django.contrib.auth.views import LoginView
from django.shortcuts import render
from django.views import View

from base.forms import LoginForm


class CustomLoginView(LoginView):
    template_name = "login.html"
    form_class = LoginForm


class FrontPageView(View):
    template_name = "front.html"

    def get(self, request):
        return render(request, self.template_name)
