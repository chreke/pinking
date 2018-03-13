from django.db import transaction
from rest_framework import mixins, viewsets, serializers
from .serializers import PinSerializer, UserSerializer
from .models import Pin


SPACE_PER_USER = 200 * 1024 * 1024  # 200 Megabytes


class PinViewSet(
        mixins.CreateModelMixin,
        mixins.DestroyModelMixin,
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        viewsets.GenericViewSet
):
    serializer_class = PinSerializer

    def get_queryset(self):
        return Pin.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        obj_size = serializer.validated_data['cumulative_size']
        with transaction.atomic():
            space_used = self._space_used(self.request.user)
            if obj_size + space_used < SPACE_PER_USER:
                serializer.save(user=self.request.user)
            else:
                raise serializers.ValidationError(
                    'Not enough free space to pin object'
                )
