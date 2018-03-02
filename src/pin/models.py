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
    multihash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
