import logging
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver


logger = logging.getLogger(__name__)
dispatch_uid="signalhandlers_identifier"


@receiver(user_logged_in, dispatch_uid=dispatch_uid) #, sender=MyModel)
def logged_in_handler(sender, user, request, **kwargs):
    logger.info('logged in %s', user)


@receiver(user_login_failed, dispatch_uid=dispatch_uid) #, sender=MyModel)
def login_failed_handler(sender, credentials, **kwargs):
    logger.info('login failed in %s', credentials['username'] if credentials is not None and 'username' in credentials else None)


@receiver(post_save, dispatch_uid=dispatch_uid) #, sender=MyModel)
def post_save_handler(sender, instance, created, raw, **kwargs):
    pass


@receiver(post_delete, dispatch_uid=dispatch_uid) #, sender=MyModel)
def post_delete_handler(sender, instance, **kwargs):
    pass
