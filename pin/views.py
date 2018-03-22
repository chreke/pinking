from django.db import transaction
from django.contrib.auth import get_user_model
from django.db.models import F
from rest_framework import mixins, viewsets, serializers, status
from rest_framework.response import Response
from .serializers import PinSerializer, UserSerializer, DeletePinSerializer
from .models import Pin
from . import pins


SPACE_PER_USER = 200 * 1024 * 1024  # 200 Megabytes


class MeView(
        mixins.RetrieveModelMixin,
        mixins.ListModelMixin,
        viewsets.GenericViewSet
):
    serializer_class = UserSerializer

    def get_queryset(self):
        return get_user_model().objects.filter(pk=self.request.user.pk)


class PinViewSet(
        mixins.CreateModelMixin,
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        viewsets.GenericViewSet
):
    serializer_class = PinSerializer

    def get_queryset(self):
        return Pin.objects.filter(user=self.request.user)

    def create(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request},
            many=True,
            allow_empty=False,
        )
        serializer.is_valid(raise_exception=True)
        created_pins = []
        with transaction.atomic():
            for pin_data in serializer.validated_data:
                pin, created = Pin.objects.get_or_create(
                    user=request.user,
                    pin_type=pin_data['pin_type'],
                    multihash=pin_data['multihash'],
                    defaults={'block_size': pin_data['block_size']},
                )
                if not created:
                    pin.count += 1
                    pin.save()
                created_pins.append(pin)
            if pins.space_used(request.user) > SPACE_PER_USER:
                raise serializers.ValidationError('Not enough space!')
        serialized = self.serializer_class(
            created_pins,
            many=True,
            context={'request': request}
        )
        return Response(serialized.data, status=status.HTTP_201_CREATED)


class DeletePinViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = DeletePinSerializer

    def create(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request},
            many=True,
            allow_empty=False,
        )
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            for pin_data in serializer.validated_data:
                Pin.objects\
                    .filter(
                        user=request.user,
                        pin_type=pin_data['pin_type'],
                        multihash=pin_data['multihash'],
                    )\
                    .update(count=F('count') - 1)
        return Response('', status=status.HTTP_201_CREATED)
