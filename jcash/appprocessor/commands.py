import logging
from datetime import datetime, timedelta

from django.db import transaction
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.utils import timezone

from jcash.api.models import Document, Notification
from jcash.commonutils import notify, person_verify


logger = logging.getLogger(__name__)
MAX_VERIFICATION_ATTEMPTS = 3


def process_all_notifications_runner():
    logger.info('Run notifications processing')

    notifications_to_send = Notification.objects.filter(is_sended=False).all()
    for notification in notifications_to_send:
        success, message_id = notify.send_notification(notification.pk)
        notification.is_sended = success
        notification.meta['mailgun_message_id'] = message_id

        notification.save()

    logger.info('Finished notifications processing')


def verify_document(document_id):
    """
    Create OnFido check to verify user document
    """
    with transaction.atomic():
        now = timezone.now()
        document = Document.objects.select_for_update().get(id=document_id)

        if document.onfido_check_status == person_verify.STATUS_COMPLETE:
            logger.warn('Verification completed for %s, exiting', document.user.username)
            return

        if document.onfido_check_id is not None:
            logger.warn('Check exists for %s, exiting', document.user.username)
            return

        if (document.verification_started_at and
            (now - document.verification_started_at) < timedelta(minutes=5)):
            logger.info('Verification already started for %s, exiting', document.user.username)
            return

        logger.info('Start verifying process for user %s <%s>', document.user.pk, document.user.username)
        document.verification_started_at = now
        document.verification_attempts += 1
        document.save()

    if not document.user.account.onfido_applicant_id:
        applicant_id = person_verify.create_applicant(document.user.pk)
        document.user.account.onfido_applicant_id = applicant_id
        document.user.account.save()
        logger.info('Applicant %s created for %s', document.user.account.onfido_applicant_id, document.user.username)
    else:
        logger.info('Applicant for %s already exists: %s', document.user.username, document.user.account.onfido_applicant_id)

    if not document.onfido_document_id:
        document_id = person_verify.upload_document(document.user.account.onfido_applicant_id,
                                                    document.image.url,
                                                    document.ext)
        document.onfido_document_id = document_id
        document.save()
        logger.info('Document for %s uploaded: %s', document.user.username, document.onfido_document_id)
    else:
        logger.info('Document for %s already uploaded: %s', document.user.username, document.onfido_document_id)

    check_id = person_verify.create_check(document.onfido_applicant_id)
    document.onfido_check_id = check_id
    document.onfido_check_created = timezone.now()
    document.save()
    logger.info('Check for %s created: %s', document.user.username, document.onfido_check_id)


def process_all_uncomplete_verifications():
    logger.info('Run process uncomplete verifications')

    now = datetime.now()
    condition = (
        Q(onfido_check_id=None) &
        Q(verification_attempts__lt=MAX_VERIFICATION_ATTEMPTS) &
        ~Q(image='') &
        (Q(verification_started_at__lt=(now - timedelta(minutes=5))) |
         Q(verification_started_at=None))
    )
    documents_to_verify = Document.objects.filter(condition).all()
    for document in documents_to_verify:
        logger.info('Retry uncomplete document verification %s <%s> %s',
                    document.user.pk, document.user.email, document.type)
        verify_document(document.pk)

    logger.info('Finished process uncomplete verifications')
