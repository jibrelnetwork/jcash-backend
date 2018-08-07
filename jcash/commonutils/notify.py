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
                *, files: List = ()) -> Tuple[bool, str, Optional[str]]:
    if any(domain in recipient for domain in config.EMAIL_NOTIFICATIONS__SENDGRID_DOMAINS):
        success, message_id = _send_email_sendgrid(config.EMAIL_NOTIFICATIONS__SENDGRID_SENDER,
                                                   recipient,
                                                   email_subject,
                                                   email_body,
                                                   proposal_id)
        provider = 'sendgrid'
    else:
        success, message_id = _send_email_mailgun(config.EMAIL_NOTIFICATIONS__MAILGUN_SENDER,
                                                  recipient,
                                                  email_subject,
                                                  email_body,
                                                  proposal_id,
                                                  files=files)
        provider = 'mailgun'
    return success, provider, message_id


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

    # jibrel logo
    template_jibrel_logo = "jibrel-logo-for-email.png"
    with open(Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, template_jibrel_logo), 'rb') as f:
        data['files[' + template_jibrel_logo + ']'] = f.read()
    data["content[" + template_jibrel_logo + "]"] = template_jibrel_logo

    # facebook logo
    template_facebook_logo = "facebook.png"
    with open(Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, template_facebook_logo), 'rb') as f:
        data['files[' + template_facebook_logo + ']'] = f.read()
    data["content[" + template_facebook_logo + "]"] = template_facebook_logo

    # linkdin logo
    template_linkdin_logo = "linkdin.png"
    with open(Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, template_linkdin_logo), 'rb') as f:
        data['files[' + template_linkdin_logo + ']'] = f.read()
    data["content[" + template_linkdin_logo + "]"] = template_linkdin_logo

    # medium logo
    template_medium_logo = "medium.png"
    with open(Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, template_medium_logo), 'rb') as f:
        data['files[' + template_medium_logo + ']'] = f.read()
    data["content[" + template_medium_logo + "]"] = template_medium_logo

    # twitter logo
    template_twitter_logo = "twitter.png"
    with open(Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, template_twitter_logo), 'rb') as f:
        data['files[' + template_twitter_logo + ']'] = f.read()
    data["content[" + template_twitter_logo + "]"] = template_twitter_logo

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
    attachments_inline=[("jibrel-logo-for-email.png",
                         Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, "jibrel-logo-for-email.png")),
                        ("facebook.png",
                         Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, "facebook.png")),
                        ("linkdin.png",
                         Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, "linkdin.png")),
                        ("medium.png",
                         Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, "medium.png")),
                        ("twitter.png",
                         Path(EMAIL_NOTIFICATIONS__TEMPLATES_PATH, "twitter.png"))
                        ])
    logger.info('Sending notification for %s, type %s', notification.email, notification.type)
    return _send_email(
        notification.email,
        subject,
        body,
        notification.user_id,
        files=email_files
    )


def company_links():
    return {
        'company_link': config.EMAIL_TEMPLATES__COMPANY_LINK,
        'contact_support_link': config.EMAIL_TEMPLATES__CONTACT_SUPPORT_LINK,
        'facebook_link': config.EMAIL_TEMPLATES__FACEBOOK_LINK,
        'twitter_link': config.EMAIL_TEMPLATES__TWITTER_LINK,
        'linkedin_link': config.EMAIL_TEMPLATES__LINKEDIN_LINK,
        'medium_link': config.EMAIL_TEMPLATES__MEDIUM_LINK,
        'email_support': config.EMAIL_TEMPLATES__EMAIL_SUPPORT,
    }


def send_email_exchange_request(email, base_curr, rec_curr, eth_address, fx_rate, user_id = None):
    ctx = company_links()
    ctx.update({
        'base_curr': base_curr,
        'rec_curr': rec_curr,
        'eth_address': eth_address,
        'fx_rate': fx_rate,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.exchange_request, data=ctx)


def send_email_exchange_successful(email, base_curr, rec_curr, eth_address, fx_rate, user_id = None):
    ctx = company_links()
    ctx.update({
        'base_curr': base_curr,
        'rec_curr': rec_curr,
        'eth_address': eth_address,
        'fx_rate': fx_rate,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.exchange_successful, data=ctx)


def send_email_exchange_unsuccessful(email, base_curr, reason, user_id = None):
    ctx = company_links()
    ctx.update({
        'base_curr': base_curr,
        'reason': reason,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.exchange_unsuccessful, data=ctx)
    pass


def send_email_refund_successful(email, base_curr, eth_address, reason, user_id = None):
    ctx = company_links()
    ctx.update({
        'base_curr': base_curr,
        'eth_address': eth_address,
        'reason': reason,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.refund_successful, data=ctx)


def send_email_eth_address_added(email, eth_address, user_id = None):
    ctx = company_links()
    ctx.update({
        'eth_address': eth_address,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.eth_address_added, data=ctx)


def send_email_eth_address_removed(email, eth_address, user_id = None):
    ctx = company_links()
    ctx.update({
        'eth_address': eth_address,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.eth_address_removed, data=ctx)


def send_email_few_steps_away(email, jcash_url, user_id = None):
    ctx = company_links()
    ctx.update({
        'activate_url': jcash_url,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.few_steps_away, data=ctx)


def send_email_jcash_application_approved(email, jcash_url, user_id = None):
    ctx = company_links()
    ctx.update({
        'activate_url': jcash_url,
        'user_name': email,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.jcash_application_approved, data=ctx)


def send_email_jcash_application_underway(email, user_id = None):
    ctx = company_links()
    add_notification(email, user_id=user_id, type=api_models.NotificationType.jcash_application_underway, data=ctx)


def send_email_jcash_application_unsuccessful(email, user_id = None):
    ctx = company_links()
    add_notification(email, user_id=user_id, type=api_models.NotificationType.jcash_application_unsuccessful, data=ctx)


# ToDo: device?, location?
def send_email_new_login_detected(email, device, location, user_id = None):
    ctx = company_links()
    ctx.update({
        'device': device,
        'location': location,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.new_login_detected, data=ctx)


def send_email_password_reset_confirmation(email, user_id = None):
    ctx = company_links()
    add_notification(email, user_id=user_id, type=api_models.NotificationType.password_reset_confirmation, data=ctx)


def send_email_password_reset(email, activate_url, user_id = None):
    ctx = company_links()
    ctx.update({
        'activate_url': activate_url,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.password_reset, data=ctx)


def send_email_verify_email(email, activate_url, user_id = None):
    ctx = company_links()
    ctx.update({
        'activate_url': activate_url,
        'user_name': email,
    })
    add_notification(email, user_id=user_id, type=api_models.NotificationType.verify_email, data=ctx)
