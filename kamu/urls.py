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
    EmailPhoneLoginVerificationView,
    EmailPhoneLoginView,
    FrontPageView,
    GoogleLoginView,
    InviteView,
    LocalLoginView,
    RegisterPhoneNumberView,
    RegisterView,
    ShibbolethLoginView,
    VerifyEmailAddressView,
    VerifyPhoneNumberView,
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
    MembershipClaimView,
    MembershipDetailView,
    MembershipListView,
    RoleDetailView,
    RoleInviteEmailView,
    RoleInviteIdentitySearch,
    RoleInviteLdapView,
    RoleInviteView,
    RoleJoinView,
    RoleListApproverView,
    RoleListInviterView,
    RoleListOwnerView,
    RoleSearchView,
)

# Overwrite default status views
handler400 = "base.error_views.bad_request"
handler403 = "base.error_views.permission_denied"
handler404 = "base.error_views.page_not_found"
handler500 = "base.error_views.server_error"

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
    path("membership/claim/", MembershipClaimView.as_view(), name="membership-claim"),
    path("role/approver/", RoleListApproverView.as_view(), name="role-list-approver"),
    path("role/inviter/", RoleListInviterView.as_view(), name="role-list-inviter"),
    path("role/owner/", RoleListOwnerView.as_view(), name="role-list-owner"),
    path("role/search/", RoleSearchView.as_view(), name="role-search"),
    path("role/<int:pk>/", RoleDetailView.as_view(), name="role-detail"),
    path("role/<int:role_pk>/invite/", RoleInviteIdentitySearch.as_view(), name="role-invite-identity"),
    path("role/<int:role_pk>/invite/ldap/<str:uid>/", RoleInviteLdapView.as_view(), name="role-invite-ldap"),
    path("role/<int:role_pk>/invite/<int:identity_pk>/", RoleInviteView.as_view(), name="role-invite-details"),
    path("role/<int:role_pk>/invite/email/", RoleInviteEmailView.as_view(), name="role-invite-details-email"),
    path("role/<int:role_pk>/join/", RoleJoinView.as_view(), name="role-join"),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("login/invite/", InviteView.as_view(), name="login-invite"),
    path("login/shibboleth/", ShibbolethLoginView.as_view(), name="login-shibboleth"),
    path("login/google/", GoogleLoginView.as_view(), name="login-google"),
    path("login/local/", LocalLoginView.as_view(), name="login-local"),
    path("login/email/", EmailPhoneLoginView.as_view(), name="login-email"),
    path("login/email/verify/", EmailPhoneLoginVerificationView.as_view(), name="login-email-verify"),
    path("login/register/", RegisterView.as_view(), name="login-register"),
    path("login/register/email/verify/", VerifyEmailAddressView.as_view(), name="login-register-email-verify"),
    path("login/register/phone/", RegisterPhoneNumberView.as_view(), name="login-register-phone"),
    path("login/register/phone/verify/", VerifyPhoneNumberView.as_view(), name="login-register-phone-verify"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
