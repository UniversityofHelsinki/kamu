"""
URL configuration for Kamu service.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/dev/topics/http/urls/
"""

from django.conf.urls import include
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from base.views import (
    CustomLoginView,
    EmailPhoneLoginView,
    FrontPageView,
    GoogleLoginView,
    LocalLoginView,
    ShibbolethLoginView,
)
from identity.views import (
    ContactView,
    EmailAddressVerificationView,
    IdentityDetailView,
    IdentityMeView,
    IdentitySearchView,
    IdentityUpdateView,
    PhoneNumberVerificationView,
)
from kamu.routers import router
from role.views import (
    MembershipDetailView,
    MembershipListView,
    RoleCreateView,
    RoleDetailView,
    RoleJoinView,
    RoleListView,
    RoleSearchView,
)

urlpatterns = [
    path("api/v0/", include(router.urls)),
    path("i18n/", include("django.conf.urls.i18n")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/schema/swagger/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/schema/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("admin/", admin.site.urls),
    path("", FrontPageView.as_view(), name="front-page"),
    path("identity/me/", IdentityMeView.as_view(), name="identity-me"),
    path("identity/<int:pk>/", IdentityDetailView.as_view(), name="identity-detail"),
    path("identity/<int:pk>/contacts/", ContactView.as_view(), name="contact-change"),
    path("identity/search/", IdentitySearchView.as_view(), name="identity-search"),
    path("identity/<int:pk>/change/", IdentityUpdateView.as_view(), name="identity-change"),
    path("email/<int:pk>/verify/", EmailAddressVerificationView.as_view(), name="email-verify"),
    path("phone/<int:pk>/verify/", PhoneNumberVerificationView.as_view(), name="phone-verify"),
    path("membership/", MembershipListView.as_view(), name="membership-list"),
    path("membership/<int:pk>/", MembershipDetailView.as_view(), name="membership-detail"),
    path("role/", RoleListView.as_view(), name="role-list"),
    path("role/search/", RoleSearchView.as_view(), name="role-search"),
    path("role/<int:pk>/", RoleDetailView.as_view(), name="role-detail"),
    path("role/<int:role_pk>/join/", RoleJoinView.as_view(), name="role-join"),
    path("role/add/", RoleCreateView.as_view(), name="role-create"),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("login/shibboleth/", ShibbolethLoginView.as_view(), name="login-shibboleth"),
    path("login/google/", GoogleLoginView.as_view(), name="login-google"),
    path("login/local/", LocalLoginView.as_view(), name="login-local"),
    path("login/email/", EmailPhoneLoginView.as_view(), name="login-email"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
