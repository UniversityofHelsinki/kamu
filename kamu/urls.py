"""
URL configuration for Kamu service.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/dev/topics/http/urls/
"""

from django.conf.urls import include
from django.contrib import admin
from django.urls import path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from base.views import (
    CustomLoginView,
    FrontPageView,
    InviteView,
    LocalLoginView,
    LocalLogoutView,
    LoginEmailPhoneVerificationView,
    LoginEmailPhoneView,
    LoginGoogleView,
    LoginMicrosoftView,
    LoginShibbolethEdugainView,
    LoginShibbolethHakaView,
    LoginShibbolethLocalView,
    LoginSuomiFiView,
    RegistrationEmailAddressVerificationView,
    RegistrationPhoneNumberVerificationView,
    RegistrationPhoneNumberView,
    RegistrationView,
)
from identity.views import (
    ContactView,
    ContractDetailView,
    ContractListView,
    ContractSignView,
    EmailAddressVerificationView,
    IdentifierView,
    IdentityCombineView,
    IdentityDetailView,
    IdentityMeView,
    IdentitySearchView,
    IdentityUpdateView,
    PhoneNumberVerificationView,
)
from kamu.routers import router
from role.views import (
    MembershipApprovalListView,
    MembershipClaimView,
    MembershipDetailView,
    MembershipExpiringListView,
    MembershipInviteEmailView,
    MembershipInviteIdentitySearch,
    MembershipInviteLdapView,
    MembershipInviteView,
    MembershipJoinView,
    MembershipUpdateView,
    RoleDetailView,
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
    path("admin/login/", CustomLoginView.as_view(), name="login"),
    path("admin/logout/", LocalLogoutView.as_view(), name="logout"),
    path("admin/", admin.site.urls),
    path("", FrontPageView.as_view(), name="front-page"),
    path("identity/me/", IdentityMeView.as_view(), name="identity-me"),
    path("identity/<int:pk>/", IdentityDetailView.as_view(), name="identity-detail"),
    path(
        "identity/combine/<int:primary_pk>/<int:secondary_pk>/", IdentityCombineView.as_view(), name="identity-combine"
    ),
    path("identity/<int:pk>/contacts/", ContactView.as_view(), name="contact-change"),
    path("identity/<int:pk>/contracts/", ContractListView.as_view(), name="contract-list"),
    path("contract/<int:pk>/", ContractDetailView.as_view(), name="contract-detail"),
    path(
        "identity/<int:identity_pk>/contracts/<int:template_pk>/sign/",
        ContractSignView.as_view(),
        name="contract-sign",
    ),
    path("identity/search/", IdentitySearchView.as_view(), name="identity-search"),
    path("identity/<int:pk>/change/", IdentityUpdateView.as_view(), name="identity-change"),
    path("identity/<int:pk>/identifiers/", IdentifierView.as_view(), name="identity-identifier"),
    path("email/<int:pk>/verify/", EmailAddressVerificationView.as_view(), name="email-verify"),
    path("phone/<int:pk>/verify/", PhoneNumberVerificationView.as_view(), name="phone-verify"),
    path("membership/<int:pk>/", MembershipDetailView.as_view(), name="membership-detail"),
    path("membership/<int:pk>/change/", MembershipUpdateView.as_view(), name="membership-change"),
    path("membership/approval/", MembershipApprovalListView.as_view(), name="membership-approval"),
    path("membership/expiring/", MembershipExpiringListView.as_view(), name="membership-expiring"),
    path("membership/claim/", MembershipClaimView.as_view(), name="membership-claim"),
    path("role/approver/", RoleListApproverView.as_view(), name="role-list-approver"),
    path("role/inviter/", RoleListInviterView.as_view(), name="role-list-inviter"),
    path("role/owner/", RoleListOwnerView.as_view(), name="role-list-owner"),
    path("role/search/", RoleSearchView.as_view(), name="role-search"),
    path("role/<int:pk>/", RoleDetailView.as_view(), name="role-detail"),
    path("role/<int:role_pk>/invite/", MembershipInviteIdentitySearch.as_view(), name="role-invite-identity"),
    path("role/<int:role_pk>/invite/ldap/<str:uid>/", MembershipInviteLdapView.as_view(), name="role-invite-ldap"),
    path("role/<int:role_pk>/invite/<int:identity_pk>/", MembershipInviteView.as_view(), name="role-invite-details"),
    path("role/<int:role_pk>/invite/email/", MembershipInviteEmailView.as_view(), name="role-invite-details-email"),
    path("role/<int:role_pk>/join/", MembershipJoinView.as_view(), name="role-join"),
    path("login/", CustomLoginView.as_view(), name="login"),
    path("login/invite/", InviteView.as_view(), name="login-invite"),
    path("login/shibboleth/", LoginShibbolethLocalView.as_view(), name="login-shibboleth"),
    path("login/haka/", LoginShibbolethHakaView.as_view(), name="login-haka"),
    path("login/edugain/", LoginShibbolethEdugainView.as_view(), name="login-edugain"),
    path("login/google/", LoginGoogleView.as_view(), name="login-google"),
    path("login/microsoft/", LoginMicrosoftView.as_view(), name="login-microsoft"),
    path("login/suomifi/", LoginSuomiFiView.as_view(), name="login-suomifi"),
    path("login/local/", LocalLoginView.as_view(), name="login-local"),
    path("login/email/", LoginEmailPhoneView.as_view(), name="login-email"),
    path("login/email/verify/", LoginEmailPhoneVerificationView.as_view(), name="login-email-verify"),
    path("login/register/", RegistrationView.as_view(), name="login-register"),
    path(
        "login/register/email/verify/",
        RegistrationEmailAddressVerificationView.as_view(),
        name="login-register-email-verify",
    ),
    path("login/register/phone/", RegistrationPhoneNumberView.as_view(), name="login-register-phone"),
    path(
        "login/register/phone/verify/",
        RegistrationPhoneNumberVerificationView.as_view(),
        name="login-register-phone-verify",
    ),
    path("logout/", LocalLogoutView.as_view(), name="logout"),
]
