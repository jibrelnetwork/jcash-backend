from datetime import datetime
from itertools import chain
from operator import itemgetter
import logging

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext_lazy as _
from rest_framework_extensions.cache.decorators import cache_response
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework.viewsets import ModelViewSet
from django.db import transaction

from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation
from jcash.api.models import (
    Address,
    Account,
)
from jcash.api.serializers import (
    AccountSerializer,
    AddressesSerializer,
    AddressSerializer,
    AddressVerifySerializer,
    ResendEmailConfirmationSerializer,
    DocumentSerializer,
    is_user_email_confirmed,
    CurrencyRateSerializer,
    CurrencySerializer,
    ApplicationConfirmSerializer,
    ApplicationRefundSerializer,
)
from jcash.api import tasks


logger = logging.getLogger(__name__)


class AccountView(GenericAPIView):
    """
    View get/set account (profile) info.

    * Requires token authentication.

    get:
    Returns account info for current user.

    put:
    Updates account info for current user.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_classes = {
        'get': AccountSerializer,
        'put': DocumentSerializer,
    }
    parser_classes = (MultiPartParser, FormParser, JSONParser,)

    def get_serializer_class(self):
        if not hasattr(self, 'action'):
            action = 'put' if 'PUT' in self.allowed_methods else 'get'
        else:
            action = self.action

        return self.serializer_classes.get(action, AccountSerializer)

    def ensure_account(self, request):
        try:
            account = request.user.account
        except ObjectDoesNotExist:
            account = Account.objects.create(user=request.user)
        return account

    def get(self, request):
        account = self.ensure_account(request)
        self.action = request.method.lower()
        serializer = self.get_serializer_class()(account)
        return Response(serializer.data)

    def put(self, request):
        account = self.ensure_account(request)
        self.action = request.method.lower()
        serializer = self.get_serializer_class()(data=request.data)
        if serializer.is_valid():
            serializer.save(account)
            self.maybe_start_identity_verification(account)
            return Response({'success': True}, 201)
        return Response({'success': False, 'error': serializer.errors}, status=400)

    def maybe_start_identity_verification(self, account):
        #if account.document_url and not account.onfido_check_id:
        #    ga_integration.on_status_registration_complete(account)
        #    tasks.verify_user.delay(account.user.pk)
        # todo:
        pass


class ResendEmailConfirmationView(GenericAPIView):
    """
    Re-send email confirmation email
    """

    #permission_classes = (permissions.AllowAny,)
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ResendEmailConfirmationSerializer

    @cache_response(20)
    def post(self, request):
        serializer = ResendEmailConfirmationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(username=serializer.data['email'])
            except User.DoesNotExist:
                return Response({'email': [_('No such user')]}, status=400)
            else:
                send_email_confirmation(request, user)
                return Response({'details': _('Verification e-mail re-sent.')})
        return Response(serializer.errors, status=400)


class CurrencyView(APIView):
    """
    Get available currencies on the platform
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencySerializer

    def get(self, request):
        data = [{"base_currency": "eth", "rec_currency":["jAED"]}, {"base_currency": "jAED", "rec_currency":["eth"]}]
        return Response(data)


class CurrencyRateView(APIView):
    """
    Get currency info
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencyRateSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            data = {"uuid": "12ad8648-c15d-47f9-9b36-47675a3af79e", "rate": 1810.0, "rec_amount": 0.0}
            return Response(data)
        else:
            return Response(serializer.errors, status=400)


class CurrencyRatesView(GenericAPIView):
    """
    Get currency-pairs rates
    """

    permission_classes = (permissions.AllowAny,)

    @cache_response(20)
    def get(self, request):
        data = [{"currency": "eth/jAED", "rate": 1800.0},{"currency": "eth/jUSD", "rate": 700.0}]
        return Response(data)


class AddressVerifyView(GenericAPIView):
    """
    Verify account address

    * Requires token authentication.

    post:
    Verify specified address for current user.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = AddressVerifySerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response({'success':True})

        return Response({'success':False, 'error': serializer.errors}, status=400)


class AddressView(GenericAPIView):
    """
    View get/set address for account

    * Requires token authentication.

    get:
    Returns list of account addresses for current user.

    post:
    Add a new address for current user.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = AddressSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        addresses_qs = Address.objects.filter(user=request.user)
        addresses = AddressesSerializer(addresses_qs, many=True).data
        return Response(addresses)

    def post(self, request):
        logger.info('Request add address for %s', request.user.username)
        # todo:
        # if is_user_email_confirmed(request.user) is False:
        #    resp = {'detail': _('Please confirm the e-mail before submitting the own addresses')}
        #    logger.info('email address is not confirmed for %s, aborting', request.user.username)
        #    return Response(resp, status=403)

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save(request.user)
            return Response(serializer.validated_data)

        logger.info('Invalid address %s for %s',
                    serializer.data.get('address'), request.user.username)
        return Response(serializer.errors, status=400)


class UserDetailsView(APIView):
    """
    Reads UserModel fields
    Accepts GET method.

    Default display fields: pk, username, email
    Read-only fields: pk, username, email

    Returns UserModel fields.
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({'pk':request.user.pk, 'username':request.user.username, 'email':request.user.email})


class ApplicationView(APIView):
    """
    View get/set exchange application.

    * Requires token authentication.

    get:
    Returns an exchange history for current user.

    post:
    Create a new exchange application for current user.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    parser_classes = (JSONParser,)

    def get(self, request):
        return Response([{"app_uuid": "12ad8648-c15d-47f9-9b36-47675a3af79e",
                         "created_at": "2018-04-24 12:35:59",
                         "source_address": "0xf93ab5a00fab5b18c25d35a2329813203104f1e8",
                         "rec_address": "0x60cb8ecadf2a81914b46086066718737ff89af51",
                         "base_currency": "eth",
                         "rec_currency": "jAED",
                         "base_amount": 1.0,
                         "rec_amount": 1810.0,
                         "rate": 1810.0,
                         "status": "created",
                         "tx_id": "",
                         "tx_amount": 0.0}])

    def post(self, request):
        return Response({"success":True, "app_uuid": "12ad8648-c15d-47f9-9b36-47675a3af79e"})


class ApplicationConfirmView(APIView):
    """
    Confirm exchange application if incoming transaction amount less than exchange amount
    Accepts POST method.

    * Requires token authentication.

    post:
    Changes status of application to perform exchange operation
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationConfirmSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response({"success":True})

        return Response({"success":False, "error":{serializer.errors}}, status=400)



class ApplicationRefundView(APIView):
    """
    Cancel exchange application and refund
    Accepts POST method.

    * Requires token authentication.

    post:
    Changes status of application to cancel exchange operation
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationRefundSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response({"success":True})

        return Response({"success":False, "error":serializer.errors}, status=400)
