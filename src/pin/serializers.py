from rest_framework import serializers
from .models import Pin


class PinSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pin
        read_only_fields = ('user', 'created_at', 'cumulative_size')
        fields = ('user', 'created_at', 'cumulative_size', 'multihash')
