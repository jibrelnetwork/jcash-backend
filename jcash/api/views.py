from datetime import datetime
from itertools import chain
from operator import itemgetter
import logging
import coreapi
import coreschema
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
    CurrencyPair,
    Application,
)
from jcash.api.serializers import (
    AccountSerializer,
    AddressesSerializer,
    AddressSerializer,
    AddressVerifySerializer,
    ResendEmailConfirmationSerializer,
    DocumentSerializer,
    CurrencyRateSerializer,
    OpenCurrencyRateSerializer,
    CurrencySerializer,
    ApplicationSerializer,
    ApplicationsSerializer,
    ApplicationConfirmSerializer,
    ApplicationRefundSerializer,
)
from jcash.api import tasks
from jcash.commonutils import currencyrates
from jcash.settings import ACCOUNT__MAX_ADDRESSES_COUNT


logger = logging.getLogger(__name__)


class AccountView(GenericAPIView):
    """
    get:
    Returns account info for current user.

    Response example:

    ```
    {"username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}
    ```

    * Requires token authentication.

    put:
    Updates account info for current user.

    Response example:

    ```
    {"username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}
    ```

    or

    ```
    {"success": false, "error": "error description"}
    ```

    * Requires token authentication.
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

    Response example:

    ```
    [{"base_currency": "ETH","rec_currency": "jAED"},
    {"base_currency": "jAED","rec_currency": "ETH"}]
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencySerializer

    def get(self, request):
        currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True)

        data = []
        for pair in currency_pairs:
            if pair.is_buyable:
                data.append({"base_currency": pair.base_currency.display_name,
                             "rec_currency": pair.reciprocal_currency.display_name})
            if pair.is_sellable:
                data.append({"base_currency": pair.reciprocal_currency.display_name,
                             "rec_currency": pair.base_currency.display_name})
        return Response(data)


class CurrencyRateView(GenericAPIView):
    """
    get:
    Get currency rate info.
    Response example:

    ```
    {"success":true,
    "uuid":"eb5c4978-c70a-4572-9f58-72250fce6b3f",
    "rate":1799.0,"rec_amount":0.0}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencyRateSerializer
    parser_classes = (JSONParser,)

    def get_param_fields(self, view):
        fields = [
            coreapi.Field(name='base_currency', required=True, location='form',
                          schema=coreschema.String(title='Base currency')),
            coreapi.Field(name='base_amount', required=True, location='form',
                          schema=coreschema.String(title='Base amount')),
            coreapi.Field(name='rec_currency', required=True, location='form',
                          schema=coreschema.String(title='Reciprocal currency')),
        ]
        return fields

    def get(self, request):
        serializer = CurrencyRateSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            is_reverse_operation = False
            currency_pair = CurrencyPair.objects.filter(base_currency__display_name=serializer.validated_data['base_currency'],
                                                         reciprocal_currency__display_name=serializer.validated_data['rec_currency']) \
                .first()

            if not currency_pair:
                currency_pair = CurrencyPair.objects.filter(
                    base_currency__display_name=serializer.validated_data['rec_currency'],
                    reciprocal_currency__display_name=serializer.validated_data['base_currency']
                ).first()
                is_reverse_operation = True

            if not currency_pair:
                return Response({'success': False, 'error': "Currency does not exists."}, status=400)

            currency_pair_rate = currency_pair.currency_pair_rates.last()

            if not currency_pair_rate:
                return Response({'success': False, 'error': "Currency price does not exists."}, status=400)

            currency_pair_rate_price = currency_pair_rate.sell_price if is_reverse_operation else currency_pair_rate.buy_price
            if is_reverse_operation:
                currency_pair_rate_price = 1.0 / currency_pair_rate_price

            data = {"success": True,
                    "uuid": currency_pair_rate.id,
                    "rate": currency_pair_rate_price,
                    "rec_amount": currency_pair_rate_price * serializer.validated_data['base_amount']}
            return Response(data)
        else:
            return Response({'success': False, 'error': serializer.errors}, status=400)


class CurrencyRatesView(GenericAPIView):
    """
    Get currency-pairs rates.

    Response example:

    ```
    [{"currency": "ETH/jAED","rate": 1799}]
    ```
    """

    permission_classes = (permissions.AllowAny,)
    serializer_class = OpenCurrencyRateSerializer

    @cache_response(20)
    def get(self, request):
        currencyrates.feth_currency_price()
        currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True)
        data = [{"currency": pair.display_name,
                 "rate": pair.currency_pair_rates.last().buy_price \
                     if pair.currency_pair_rates.last() else 0.0 } for pair in currency_pairs]
        return Response(data)


class AddressVerifyView(GenericAPIView):
    """
    Verify account address

    post:
    Verify specified address for current user.

    Response example:

    ```
    {"success": true}
    ```

    or

    ```
    {"success": false, "error": "error description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = AddressVerifySerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'success':True})

        return Response({'success':False, 'error': serializer.errors}, status=400)


class AddressView(GenericAPIView):
    """
    View get/set address for account

    get:
    Returns list of account addresses for current user.

    Response example:

    ```
    [{"address": "0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2",
      "type": "eth",
      "is_verified": true}]
    ```

    * Requires token authentication.

    post:
    Add a new address for current user.

    Response example:

    ```
    {"success":true,
     "address":"0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2",
     "type":"eth",
     "is_verified":false,
     "message":"I, Ivan Ivanov, hereby confirm that I and only I own and have access to the private key of
     the address 0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2. Date: 2018 May 23 06:40 AM UTC",
     "uuid":"a357e783-bcad-4d1e-a6d1-b0e80aec31e0",
     "success":true}
    ```

    or

    ```
    {"success": false, "error": "error description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = AddressSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        addresses_qs = Address.objects.filter(user=request.user)
        addresses = AddressesSerializer(addresses_qs, many=True).data
        return Response(addresses)

    def post(self, request):
        if Account.is_user_email_confirmed(request.user) is False:
            return Response({"success": False, "error":"Please confirm the e-mail before submitting the own addresses"}, status=400)

        if not request.user.account.is_identity_verified:
            return Response({"success": False, "error":"Personal data is not verified yet."}, status=400)

        addresses = Address.objects.filter(user=request.user)
        if len(addresses) >= ACCOUNT__MAX_ADDRESSES_COUNT:
            return Response({"success": False, "error": "Couldn't add new address. Too many addresses."}, status=400)

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(request.user)
            return Response(serializer.validated_data)

        return Response({"success": False, "error": serializer.errors}, status=400)


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


class ApplicationView(GenericAPIView):
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
    serializer_class = ApplicationSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        applications_qs = Application.objects.filter(user=request.user)
        applications = ApplicationsSerializer(applications_qs, many=True).data
        return Response(applications)

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success":True, "app_uuid": serializer.validated_data['application_id']})
        else:
            return Response({"success": False, "error": serializer.errors})


class ApplicationConfirmView(GenericAPIView):
    """
    Confirm exchange application if incoming transaction amount less than exchange amount
    Accepts POST method.

    post:
    Changes status of application to perform exchange operation.

    Returns the success/fail message.

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationConfirmSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success":True})

        return Response({"success":False, "error":{serializer.errors}}, status=400)



class ApplicationRefundView(GenericAPIView):
    """
    Cancel exchange application and refund
    Accepts POST method.

    post:
    Changes status of application to cancel exchange operation end refund.

    Returns the success/fail message.

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationRefundSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
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
        else:
            serializer_data =  TokenSerializer(user.auth_token).data
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
