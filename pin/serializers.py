from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Pin
from . import pins


class PinSerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Pin
        read_only_fields = ('count', 'created_at',)
        fields = (
            'block_size',
            'count',
            'created_at',
            'multihash',
            'pin_type',
            'url',
        )


class DeletePinSerializer(serializers.Serializer):
    multihash = serializers.CharField(max_length=64)
    pin_type = serializers.ChoiceField(choices=Pin.PIN_TYPE_CHOICES)


class UserSerializer(serializers.ModelSerializer):
    space_used = serializers.SerializerMethodField()

    class Meta:
        model = get_user_model()
        read_only_fields = ('username', 'email')
        fields = ('username', 'email', 'space_used')

    def get_space_used(self, user):
        return pins.space_used(user)
