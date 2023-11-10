"""
Identity app views for API endpoints.
"""

from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from identity.models import EmailAddress, Identifier, Identity, PhoneNumber
from identity.serializers import (
    EmailAddressSerializer,
    IdentifierSerializer,
    IdentitySerializer,
    PhoneNumberSerializer,
)


class EmailAddressViewSet(viewsets.ModelViewSet):
    """
    API endpoint for email addresses.
    """

    queryset = EmailAddress.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = EmailAddressSerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user if user is not a superuser.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return EmailAddress.objects.all()
        return EmailAddress.objects.filter(identity__user=user)


class PhoneNumberViewSet(viewsets.ModelViewSet):
    """
    API endpoint for phone numbers.
    """

    queryset = PhoneNumber.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = PhoneNumberSerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user if user is not a superuser.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return PhoneNumber.objects.all()
        return PhoneNumber.objects.filter(identity__user=user)


class IdentifierViewSet(viewsets.ModelViewSet):
    """
    API endpoint for unique identifiers.
    """

    queryset = Identifier.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = IdentifierSerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user, if user is not a superuser.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return Identifier.objects.all()
        return Identifier.objects.filter(identity__user=user)


class IdentityViewSet(viewsets.ModelViewSet):
    """
    API endpoint for identities.
    """

    queryset = Identity.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = IdentitySerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user, if user is not a superuser.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return Identity.objects.all()
        return Identity.objects.filter(user=user)
