import logging
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver


logger = logging.getLogger(__name__)
dispatch_uid="signalhandlers_identifier"


@receiver(user_logged_in, dispatch_uid=dispatch_uid)
def logged_in_handler(sender, user, request, **kwargs):
    logger.info('logged in %s', user)


@receiver(user_login_failed, dispatch_uid=dispatch_uid)
def login_failed_handler(sender, credentials, **kwargs):
    logger.info('login failed in %s', credentials['username'] if credentials is not None and 'username' in credentials else None)
