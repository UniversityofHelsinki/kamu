from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import translation


def _send_email(subject, message, from_email=None, recipient_list=None) -> bool:
    """
    Send email using Django's send_email function, returning success as bool.

    Use TOKEN_FROM_EMAIL as default.
    """
    if not from_email:
        from_email = getattr(settings, "TOKEN_FROM_EMAIL", None)
    if send_mail(subject, message, from_email, recipient_list, fail_silently=True):
        return True
    return False


def _get_link_url(request=None, view_name="front-page") -> str | None:
    """
    Get link URL for email messages.

    Use base from the settings if available, otherwise build from request or return None.
    """
    service_link_url = getattr(settings, "SERVICE_LINK_URL", None)
    if service_link_url:
        return service_link_url + reverse(view_name)
    elif request:
        return request.build_absolute_uri(reverse(view_name))
    return None


def send_invite_email(membership, token, address, lang="en", request=None) -> bool:
    """
    Send a role invite by email.
    """
    cur_language = translation.get_language()
    link_url = _get_link_url(request, "login-invite")
    try:
        translation.activate(lang)
        subject = render_to_string("email/invite_email_subject.txt")
        message = render_to_string(
            "email/invite_email_message.txt",
            {
                "inviter": membership.inviter.get_full_name(),
                "role": membership.role.name(),
                "token": token,
                "link_url": link_url,
            },
        )
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[address])


def send_verification_email(token, email_address, lang="en") -> bool:
    """
    Send a verification email.
    """

    cur_language = translation.get_language()
    try:
        translation.activate(lang)
        subject = render_to_string("email/verification_email_subject.txt")
        message = render_to_string("email/verification_email_message.txt", {"token": token})
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[email_address])
