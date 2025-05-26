from typing import Any

from django.conf import settings
from django.views.generic import TemplateView


class AccessibilityStatementView(TemplateView):
    """
    View for the accessibility statement page.
    """

    template_name = "accessibility_statement.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["contact_email"] = getattr(settings, "ACCESSIBILITY_CONTACT_EMAIL", "")
        return context
