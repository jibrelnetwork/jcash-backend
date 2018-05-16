from datetime import datetime
from itertools import chain
from operator import itemgetter
import logging

from allauth.account import app_settings as allauth_settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model, logout as django_logout
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext_lazy as _
from rest_framework_extensions.cache.decorators import cache_response
from rest_framework.parsers import JSONParser, FormParser, MultiPartParser
from rest_framework.viewsets import ModelViewSet
from rest_framework import status
from rest_auth.registration.views import RegisterView as RestAuthRegisterView, VerifyEmailView
from django.db import transaction
from rest_auth.app_settings import (
    PasswordChangeSerializer,
    TokenSerializer,
    JWTSerializer
)
from rest_auth.views import (
    PasswordChangeView, PasswordResetView, PasswordResetConfirmView, LogoutView
)

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
            serializer_get = self.serializer_classes.get('get')(account)
            return Response(serializer_get.data, 201)
        return Response({'error': serializer.errors}, status=400)

    def maybe_start_identity_verification(self, account):
        #if account.document_url and not account.onfido_check_id:
        #    ga_integration.on_status_registration_complete(account)
        #    tasks.verify_user.delay(account.user.pk)
        # todo:
        pass


class ResendEmailConfirmationView(GenericAPIView):
    """
    Resend email confirmation.

    * Requires token authentication.

    post:
    Resend email confirmation.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ResendEmailConfirmationSerializer

    @cache_response(20)
    def post(self, request):
        serializer = ResendEmailConfirmationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(username=serializer.data['email'])
            except User.DoesNotExist:
                return Response({'success': False, 'error': [_('No such user')]}, status=400)
            else:
                send_email_confirmation(request, user)
                return Response({'success': True})
        return Response(serializer.errors, status=400)


class CurrencyView(APIView):
    """
    Get available currencies on the platform.

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencySerializer

    def get(self, request):
        data = [{"base_currency": "eth", "rec_currency":["jAED"]}, {"base_currency": "jAED", "rec_currency":["eth"]}]
        return Response(data)


class CurrencyRateView(APIView):
    """
    Get currency info.

    * Requires token authentication.
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
    Get currency-pairs rates.
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


class CustomUserDetailsView(APIView):
    """
    Reads UserModel fields
    Accepts GET method.

    * Requires token authentication.

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


class RegisterView(RestAuthRegisterView):
    """
    User registration.

    * Requires token authentification.
    """
    def get_response_data(self, user):
        if allauth_settings.EMAIL_VERIFICATION == \
                allauth_settings.EmailVerificationMethod.MANDATORY:
            return {"detail": _("Verification e-mail sent.")}

        if getattr(settings, 'REST_USE_JWT', False):
            data = {
                'user': user,
                'token': self.token
            }
            serializer_data = JWTSerializer(data).data
            #serializer_data['success'] = True
        else:
            serializer_data =  TokenSerializer(user.auth_token).data
            #serializer_data['success'] = True
        return serializer_data


class CustomPasswordChangeView(PasswordChangeView):
    """
    Calls Django Auth SetPasswordForm save method.

    Accepts the following POST parameters: old_password, new_password

    Returns the success/fail message.

    * Requires token authentification.
    """
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"success": True})


class CustomPasswordResetView(PasswordResetView):
    """
    Calls Django Auth PasswordResetForm save method.

    Accepts the following POST parameters: email
    Returns the success/fail message.
    """
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        # Return the success message with OK HTTP status
        return Response(
            {"success": True},
            status=status.HTTP_200_OK
        )


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """
    Password reset e-mail link is confirmed, therefore
    this resets the user's password.

    Accepts the following POST parameters: token, uid,
        new_password
    Returns the success/fail message.
    """
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"success": True}
        )


class CustomVerifyEmailView(VerifyEmailView):
    """
    Email confirmation.

    Accepts the following POST parameters: email
    Returns the success/fail message.
    """
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.kwargs['key'] = serializer.validated_data['key']
        confirmation = self.get_object()
        confirmation.confirm(self.request)
        return Response({'success': True}, status=status.HTTP_200_OK)


class CustomLogoutView(LogoutView):
    """
    Calls Django logout method and delete the Token object
    assigned to the current User object.

    Accepts/Returns nothing.
    """
    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass

        django_logout(request)

        return Response({"success": True},
                        status=status.HTTP_200_OK)