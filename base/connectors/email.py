from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
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


def send_invite_email(membership, token, address, lang="en") -> bool:
    """
    Send a role invite by email.
    """
    cur_language = translation.get_language()
    try:
        translation.activate(lang)
        subject = render_to_string("email/invite_email_subject.txt")
        message = render_to_string(
            "email/invite_email_message.txt",
            {"inviter": membership.inviter.get_full_name(), "role": membership.role.name(), "token": token},
        )
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[address])
