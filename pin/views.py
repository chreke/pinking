from rest_framework import mixins, viewsets
from .serializers import PinSerializer
from .models import Pin
from .ipfs import MockIPFS


class PinViewSet(
        mixins.CreateModelMixin,
        mixins.DestroyModelMixin,
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        viewsets.GenericViewSet
):
    queryset = Pin.objects.all()
    serializer_class = PinSerializer

    def perform_create(self, serializer):
        ipfs = MockIPFS('0.0.0.0')
        multihash = serializer.validated_data['multihash']
        serializer.save(
            user=self.request.user,
            cumulative_size=ipfs.get_cumulative_size(multihash),
        )
