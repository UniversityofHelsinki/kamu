from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from identity.models import Identity
from identity.serializers import IdentitySerializer


class IdentityViewSet(viewsets.ModelViewSet):
    """API endpoint for identities"""

    queryset = Identity.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = IdentitySerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user if user is not a superuser
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return Identity.objects.all()
        return Identity.objects.filter(user=user)
