from datetime import timedelta

from django.core.exceptions import ImproperlyConfigured
from django.db import models, transaction
from django.utils import timezone

from .settings import oauth2_settings

from .abstract_models import (
    AbstractApplication,
    AbstractGrant,
    AbstractAccessToken,
    AbstractRefreshToken,
    get_access_token_model,
    get_grant_model,
    get_refresh_token_model,
    get_application_model,
)


class ApplicationManager(models.Manager):
    def get_by_natural_key(self, client_id):
        return self.get(client_id=client_id)


class Application(AbstractApplication):
    objects = ApplicationManager()

    class Meta(AbstractApplication.Meta):
        swappable = "OAUTH2_PROVIDER_APPLICATION_MODEL"

    def natural_key(self):
        return (self.client_id,)


class Grant(AbstractGrant):
    class Meta(AbstractGrant.Meta):
        swappable = "OAUTH2_PROVIDER_GRANT_MODEL"


class AccessToken(AbstractAccessToken):
    class Meta(AbstractAccessToken.Meta):
        swappable = "OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL"


class RefreshToken(AbstractRefreshToken):
    class Meta(AbstractRefreshToken.Meta):
        swappable = "OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL"


def clear_expired():
    now = timezone.now()
    refresh_expire_at = None
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    grant_model = get_grant_model()
    REFRESH_TOKEN_EXPIRE_SECONDS = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS
    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    with transaction.atomic():
        if refresh_expire_at:
            refresh_token_model.objects.filter(revoked__lt=refresh_expire_at).delete()
            refresh_token_model.objects.filter(access_token__expires__lt=refresh_expire_at).delete()
        access_token_model.objects.filter(refresh_token__isnull=True, expires__lt=now).delete()
        grant_model.objects.filter(expires__lt=now).delete()
