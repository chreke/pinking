from django.conf import settings
from django.db import models


class Pin(models.Model):
    RECURSIVE = 1
    INDIRECT = 2
    MFS_ROOT = 3
    PIN_TYPE_CHOICES = (
        (RECURSIVE, 'Recursive'),
        (INDIRECT, 'Indirect'),
        (MFS_ROOT, 'MFS root'),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    block_size = models.PositiveIntegerField()
    pin_type = models.PositiveIntegerField(choices=PIN_TYPE_CHOICES)
    multihash = models.CharField(
        max_length=64,
        db_index=True,
        help_text='The multihash of the IPFS object to pin',
    )
    created_at = models.DateTimeField(auto_now_add=True)
