from rest_framework import serializers
from .models import Pin


class PinSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Pin
        read_only_fields = ('created_at',)
        fields = ('created_at', 'cumulative_size', 'multihash', 'url')
