from django.conf import settings
from django.db import models


class Pin(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    cumulative_size = models.PositiveIntegerField(
        help_text='Total size of object and its references in bytes'
    )
    multihash = models.CharField(
        max_length=64,
        db_index=True,
        help_text='The multihash of the IPFS object to pin',
    )
    created_at = models.DateTimeField(auto_now_add=True)
