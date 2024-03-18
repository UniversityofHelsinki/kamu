"""
Serializer mixins
"""

from django.db.models import QuerySet


class EagerLoadingMixin:
    """
    Mixin to set select_related and prefetch_related to queryset.
    From the comments of http://ses4j.github.io/2015/11/23/optimizing-slow-django-rest-framework-performance/
    """

    @classmethod
    def setup_eager_loading(cls, queryset: QuerySet) -> QuerySet:
        """
        Sets select_related and prefetch_related attributes to queryset if specified in serializer.
        """
        if hasattr(cls, "_SELECT_RELATED_FIELDS"):
            queryset = queryset.select_related(*cls._SELECT_RELATED_FIELDS)
        if hasattr(cls, "_PREFETCH_RELATED_FIELDS"):
            queryset = queryset.prefetch_related(*cls._PREFETCH_RELATED_FIELDS)
        return queryset
