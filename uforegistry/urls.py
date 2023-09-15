"""
URL configuration for uforegistry project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import include
from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from identity.views import FrontPageView, IdentityView
from role.views import (
    MembershipDetailView,
    RoleCreateView,
    RoleDetailView,
    RoleJoinView,
    RoleListView,
)
from uforegistry.routers import router

urlpatterns = [
    path("api/v0/", include(router.urls)),
    path("i18n/", include("django.conf.urls.i18n")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/schema/swagger/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("admin/", admin.site.urls),
    path("", FrontPageView.as_view(), name="front-page"),
    path("identity/", IdentityView.as_view(), name="identity"),
    path("membership/<int:pk>/", MembershipDetailView.as_view(), name="membership-detail"),
    path("roles/", RoleListView.as_view(), name="role-list"),
    path("roles/<int:pk>/", RoleDetailView.as_view(), name="role-detail"),
    path("role/<int:role_pk>/join/", RoleJoinView.as_view(), name="role-join"),
    path("role/add/", RoleCreateView.as_view(), name="role-create"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
