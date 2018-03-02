from rest_framework import viewsets
from .serializers import PinSerializer
from .models import Pin


class PinViewSet(viewsets.ModelViewSet):
    queryset = Pin.objects.all()
    serializer_class = PinSerializer
