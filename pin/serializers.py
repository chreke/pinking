from django.conf import settings
from rest_framework import serializers
from .models import Pin
from . import pins


class PinSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Pin
        read_only_fields = ('created_at',)
        fields = ('created_at', 'cumulative_size', 'multihash', 'url')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        settings.AUTH_USER_MODEL
        read_only_fields = ('username', 'email', 'space_used',)

    def get_space_used(user):
        return pins.space_used(user)
