#!/usr/bin/env python

import os
import logging
import requests
import time
import sys
import traceback
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from email.utils import formatdate
from jinja2 import FileSystemLoader, Environment
from jcash.api import models as api_models
from jcash import settings as config


EMAIL_NOTIFICATIONS__TEMPLATES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'api', 'templates')
logger = logging.getLogger(__name__)


def _format_jnt_value(value: float) -> str:
    return "{0:.0f}".format(int(value))


def _format_jnt_value_subject(value: float) -> str:
    return "{0:.0f}".format(int(value))


def _format_fiat_value(value: float) -> str:
    return "{0:.2f}".format(value)


def _format_coin_value(value: float) -> str:
    return "{0:.2f}".format(value)


def _format_conversion_rate(value: float) -> str:
    return "{0:.2f}".format(value)


def _format_date_period(start_date: datetime, end_date: datetime) -> str:
    return '{0:%d %b %Y} - {1:%d %b %Y}'.format(start_date, end_date)


def _format_email_files(*,
                        attachments: List[Tuple[str, Path]] = (),
                        attachments_inline: List[Tuple[str, Path]] = ()) -> List:
    # read attachments
    attachments_data = []  # type: List[Tuple[str, bytes]]
    for attachment_name, attachment_path in attachments:
        attachment_bytes = attachment_path.read_bytes()
        attachments_data.append((attachment_name, attachment_bytes))

    attachments_inline_data = []  # type: List[Tuple[str, bytes]]
    for attachment_name, attachment_path in attachments_inline:
        attachment_bytes = attachment_path.read_bytes()
        attachments_inline_data.append((attachment_name, attachment_bytes))

    # format files
    files = []
    for attachment_name, attachment_bytes in attachments_data:
        files.append(("attachment", (attachment_name, attachment_bytes)))
    for attachment_name, attachment_bytes in attachments_inline_data:
        files.append(("inline", (attachment_name, attachment_bytes)))

    return files


def _send_email(recipient: str,
                email_subject: str,
                email_body: str,
                proposal_id: str,
                *, files: List = ()) -> Tuple[bool, Optional[str]]:

    if any(domain in recipient for domain in config.EMAIL_NOTIFICATIONS__SENDGRID_DOMAINS):
        return _send_email_sendgrid(config.EMAIL_NOTIFICATIONS__SENDGRID_SENDER,
                                    recipient,
                                    email_subject,
                                    email_body,
                                    proposal_id)
    else:
        return _send_email_mailgun(config.EMAIL_NOTIFICATIONS__MAILGUN_SENDER,
                                   recipient,
                                   email_subject,
                                   email_body,
                                   proposal_id,
                                   files=files)


def _send_email_mailgun(sender: str,
                recipient: str,
                email_subject: str,
                email_body: str,
                proposal_id: str,
                *, files: List = ()) -> Tuple[bool, Optional[str]]:
    # send data
    max_attempts = 2
    success = True
    message_id = None

    for attempt in range(max_attempts):
        # noinspection PyBroadException
        try:
            data = {
                "from": sender,
                "to": recipient,
                "subject": email_subject,
                "html": email_body
            }
            response = requests.post(config.MAILGUN__API_MESSAGES_URL, auth=("api", config.MAILGUN__API_KEY), data=data, files=files)
            # check that a request is successful
            response.raise_for_status()

            message_id = response.json().get("id")

            break
        except Exception:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            if attempt < max_attempts - 1:
                logging.getLogger(__name__).error(("Failed to send email '{}' to '{}' due to error." +
                                                   " Sleep and try again.\n{}")
                                                  .format(proposal_id, recipient, exception_str))
                time.sleep(20)
            else:
                logging.getLogger(__name__).error("Failed to send email '{}' to '{}' due to error. Abort.\n{}"
                                                  .format(proposal_id, recipient, exception_str))
                success = False

    if config.EMAIL_NOTIFICATIONS__BACKUP_ENABLED:
        # noinspection PyBroadException
        try:
            data = {
                "from": config.EMAIL_NOTIFICATIONS__BACKUP_SENDER,
                "to": config.EMAIL_NOTIFICATIONS__BACKUP_ADDRESS,
                "subject": email_subject + ' >>> ' + recipient,
                "html": email_body
            }

            requests.post(config.MAILGUN__API_MESSAGES_URL, auth=("api", config.MAILGUN__API_KEY), data=data, files=files)
        except Exception:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            logging.getLogger(__name__).error("Failed to send backup email '{}' due to error:\n{}"
                                              .format(proposal_id, exception_str))

    return success, message_id


def _send_email_sendgrid(sender: str,
                         recipient: str,
                         email_subject: str,
                         email_body: str,
                         proposal_id: str) -> Tuple[bool, Optional[str]]:
    data = {
        "from": sender,
        "to": recipient,
        "subject": email_subject,
        "html": email_body
    }

    template_logo = "jibrel_logo.png"
    with open(Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, template_logo), 'rb') as f:
        data['files[' + template_logo + ']'] = f.read()
    data["content[" + template_logo + "]"] = template_logo

    # send data
    max_attempts = 2
    success = True
    message_id = None

    for attempt in range(max_attempts):
        # noinspection PyBroadException
        try:
            response = requests.post(config.SENDGRID__API_MESSAGES_URL,
                                     data=data,
                                     headers = {
                                                "Authorization": "Bearer {}".format(config.SENDGRID__API_KEY),
                                                "Accept": "*/*"
                                                }
                                     )
            # check that a request is successful
            response.raise_for_status()

            message_id = str(uuid.uuid4())

            break
        except Exception:
            exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
            if attempt < max_attempts - 1:
                logging.getLogger(__name__).error(("Failed to send email '{}' to '{}' due to error." +
                                                   " Sleep and try again.\n{}")
                                                  .format(proposal_id, recipient, exception_str))
                time.sleep(20)
            else:
                logging.getLogger(__name__).error("Failed to send email '{}' to '{}' due to error. Abort.\n{}"
                                                  .format(proposal_id, recipient, exception_str))
                success = False

    return success, message_id


#
# Persist notification to the database
#

def add_notification(email: str, type: str, user_id: Optional[int] = None, data: Optional[dict] = None):
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start persist notification to the database. email: {}, user_id: {}"
                                         .format(email, user_id))

        if user_id:
            try:
                api_models.Account.objects.get(user_id=user_id)
            except (ValueError, api_models.Account.DoesNotExist):
                logging.getLogger(__name__).error("Invalid user_id: {}.".format(user_id))

        api_models.Notification.objects.create(
            user_id=user_id,
            type=type,
            email=email,
            rendered_message=api_models.Notification.get_body(type, data if data else dict()),
            meta=data if data else dict()
        )

        logging.getLogger(__name__).info("Finished to persist notification to the database. email: {}, account_id: {}"
                                         .format(email, user_id))

        return True
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error(
            "Failed to persist notification to the database due to exception:\n{}".format(exception_str))
        return False


def send_notification(notification_id):
    """
    Sending notification
    """
    notification = api_models.Notification.objects.get(pk=notification_id)

    if notification.is_sended:
        logger.warn('Notification #%s aready sent', notification_id)
        return False, None

    subject = notification.get_subject(notification.type, notification.meta)
    body = notification.get_body(notification.type, notification.meta)
    email_files = _format_email_files(
    attachments_inline=[("jibrel_logo.png",
                         Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, "jibrel_logo.png"))])
    logger.info('Sending notification for %s, type %s', notification.email, notification.type)
    return _send_email(
        notification.email,
        subject,
        body,
        notification.user_id,
        files=email_files
    )


def send_email_verify_email(email, activate_url, user_id=None):
    ctx = {
        'activate_url': activate_url,
    }
    add_notification(email, user_id=user_id, type=api_models.NotificationType.account_created, data=ctx)


def send_email_reset_password(email, activate_url, user_id=None):
    ctx = {
        'activate_url': activate_url,
    }
    add_notification(email, user_id=user_id, type=api_models.NotificationType.password_change_request, data=ctx)


def send_email_kyc_account_rejected(email, reason, user_id=None):
    ctx = {
        'reason': reason,
    }
    add_notification(email, user_id=user_id, type=api_models.NotificationType.kyc_account_rejected, data=ctx)


def send_email_kyc_account_approved(email, user_id=None):
    add_notification(email, user_id=user_id, type=api_models.NotificationType.kyc_account_approved, data={})
