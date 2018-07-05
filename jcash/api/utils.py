import csv
import io
import zipfile

from allauth.account.adapter import DefaultAccountAdapter, build_absolute_uri
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model
from rest_framework.views import exception_handler
from rest_framework import exceptions
from django.utils.encoding import force_text

from jcash.api.models import Address, Account
from jcash.api.views import AccountView
from jcash.commonutils.notify import send_email_verify_email
from jcash.settings import FRONTEND_URL

import logging


logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, exceptions.APIException) and \
            response is not None and \
            isinstance(response.data, dict):

        error = None
        errors = None
        if ("non_field_errors" in response.data.keys() or "detail" in response.data.keys()) \
                and len(response.data.keys())==1:
            error = " ".join("{}".format(force_text("".join(value))) for field, value in response.data.items())
        else:
            errors = response.data

        if 'view' in context and \
            isinstance(context['view'], AccountView) and \
            context['request'].method=="PUT":
            if error:
                response.data = {'error': error}
            else:
                response.data = {'errors': errors}
        else:
            if error:
                response.data = {'success': False, 'error': error}
            else:
                response.data = {'success': False, 'errors': errors}

    return response


class AccountAdapter(DefaultAccountAdapter):

    def get_email_confirmation_url(self, request, emailconfirmation):
        """Constructs the email confirmation (activation) url.
        Note that if you have architected your system such that email
        confirmations are sent outside of the request context `request`
        can be `None` here.
        """
        return FRONTEND_URL + '/auth/signup/email-verify/' + emailconfirmation.key

    def send_confirmation_mail(self, request, emailconfirmation, signup):
        activate_url = self.get_email_confirmation_url(
            request,
            emailconfirmation)

        send_email_verify_email(emailconfirmation.email_address.email,
                                activate_url,
                                emailconfirmation.email_address.user.pk)
