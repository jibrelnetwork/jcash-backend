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

import logging


logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if isinstance(exc, exceptions.APIException) and \
            response is not None and \
            isinstance(response.data, dict):

        error = " ".join("{}: {}".format(force_text(field), force_text("".join(value))) for field, value in response.data.items())

        if 'view' in context and \
            isinstance(context['view'], AccountView) and \
            context['request'].method=="PUT":

            response.data = {'error': error}
        else:
            response.data = {'success': False, 'error': error}

    return response


class AccountAdapter(DefaultAccountAdapter):

    def get_email_confirmation_url(self, request, emailconfirmation):
        """Constructs the email confirmation (activation) url.
        Note that if you have architected your system such that email
        confirmations are sent outside of the request context `request`
        can be `None` here.
        """
        return build_absolute_uri(None, '/') + '#/auth/signup/verify/' + emailconfirmation.key

    def send_confirmation_mail(self, request, emailconfirmation, signup):
        activate_url = self.get_email_confirmation_url(
            request,
            emailconfirmation)

        send_email_verify_email(emailconfirmation.email_address.email,
                                activate_url,
                                emailconfirmation.email_address.user.pk)
