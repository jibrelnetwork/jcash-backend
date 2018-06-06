from datetime import datetime
from itertools import chain
from operator import itemgetter
import logging
import coreapi
import coreschema
import inspect
import sys
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
    PasswordChangeView, PasswordResetView, PasswordResetConfirmView, LogoutView, LoginView
)
from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation
from jcash.api.models import (
    Address,
    Account,
    AccountStatus,
    CurrencyPair,
    Application,
    ApplicationStatus,
    ObjStatus,
)
from jcash.api.serializers import (
    AccountSerializer,
    AddressesSerializer,
    AddressSerializer,
    RemoveAddressSerializer,
    AddressVerifySerializer,
    AccountInitSerializer,
    AccountUpdateSerializer,
    CurrencyRateSerializer,
    OpenCurrencyRateSerializer,
    CurrencySerializer,
    ApplicationSerializer,
    ApplicationsSerializer,
    ApplicationConfirmSerializer,
    ApplicationRefundSerializer,
    ApplicationFinishSerializer,
    ApplicationCancelSerializer,
    ResendEmailConfirmationSerializer,
)
from jcash.commonutils import currencyrates
from jcash.settings import LOGIC__MAX_ADDRESSES_NUM


logger = logging.getLogger(__name__)


def get_status_class_members(obj):
    def get_description(obj, attr):
        return "<mark>{}</mark> - {}".format(getattr(getattr(obj,attr), 'name'),
                                getattr(getattr(obj,attr), 'description'))

    _obj = obj()
    return ", ".join([get_description(_obj, attr) for attr in dir(_obj) \
                         if not callable(getattr(_obj, attr)) and not attr.startswith("__")])


def docstring_parameter(*sub):
    def dec(obj):
        obj.__doc__ = obj.__doc__.format(*sub)
        return obj
    return dec


@docstring_parameter(get_status_class_members(AccountStatus))
class AccountUpdateView(GenericAPIView):
    """
    post:
    Updates account info for current user.

    Response example:

    ```
    {{"success":true,
     "username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}}
    ```

    or

    ```{{"success": false, "error": "error description"}}```

    ```{{"success": false, "errors": {{"field_name":"error_description"}}}}```

    post:
    Set account info for current user.

    Response example:

    ```
    {{"success":true,
     "username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}}
     ```

    **Statuses**

    {0}

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_classes = {
        'get': AccountSerializer,
        'post': AccountUpdateSerializer
    }
    parser_classes = (JSONParser,)

    def get_serializer_class(self):
        return AccountUpdateSerializer

    def ensure_account(self, request):
        try:
            account = request.user.account
        except ObjectDoesNotExist:
            account = Account.objects.create(user=request.user)
        return account

    def update_account_info(self, request):
        account = self.ensure_account(request)
        self.action = request.method.lower()
        serializer_class = self.serializer_classes.get(self.action)
        serializer = serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save(account)
            self.maybe_start_identity_verification(account)
            serializer_get = self.serializer_classes.get('get')(account)

            return Response(serializer_get.data, 201)

    def post(self, request):
        return self.update_account_info(request)

    def maybe_start_identity_verification(self, account):
        #if account.document_url and not account.onfido_check_id:
        #    ga_integration.on_status_registration_complete(account)
        #    tasks.verify_user.delay(account.user.pk)
        # todo:
        pass


@docstring_parameter(get_status_class_members(AccountStatus))
class AccountView(AccountUpdateView):
    """
    get:
    Returns account info for current user.

    Response example

    ```
    {{"success":true,
     "username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}}
    ```

    **Statuses**

    {0}

    * Requires token authentication.

    put:
    Updates account info for current user.

    Response example:

    ```
    {{"success":true,
     "username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}}
    ```

    or

    ```{{"success": false, "error": "error description"}}```

    ```{{"success": false, "errors": {{"field_name":"error_description"}}}}```

    post:
    Set account info for current user.

    Response example:

    ```
    {{"success":true,
     "username":"ivan.ivanov@example.com",
     "first_name":"Ivan",
     "last_name":"Ivanov",
     "birthday":"1971-01-01",
     "citizenship":"Russia",
     "residency":"Russia",
     "is_identity_verified":true,
     "is_identity_declined":false,
     "is_email_confirmed":true,
     "status":"verified"}}
    ```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_classes = {
        'get': AccountSerializer,
        'post': AccountInitSerializer
    }
    parser_classes = (MultiPartParser,)

    def get_serializer_class(self):
        """
        Get serializer class.
        Attention! Do not use it (documentation API only)
        :return: serializer
        """
        action = 'get'
        if not hasattr(self, 'action'):
            frame = sys._getframe(2)
            if frame:
                args = inspect.getargvalues(frame)
                if args and 'method' in args.locals and 'path' in args.locals:
                    action = args.locals['method'].lower()

        return self.serializer_classes.get(action, AccountSerializer)

    def get(self, request):
        account = self.ensure_account(request)
        self.action = request.method.lower()
        serializer = AccountSerializer(account)
        return Response(serializer.data)

    def post(self, request):
        return self.update_account_info(request)


class ResendEmailConfirmationView(GenericAPIView):
    """
    Resend email confirmation.

    * Requires token authentication.

    post:
    Resend email confirmation.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ResendEmailConfirmationSerializer

    def post(self, request):
        try:
            send_email_confirmation(request, request.user)
        except:
            return Response({'success': False, 'error': [_('Resend email confirmation failed')]}, status=400)
        return Response({'success': True})


class CurrencyView(APIView):
    """
    Get available currencies on the platform.

    Response example:

    ```
    {"success":true,"currencies":[{"base_currency":"ETH","rec_currency":"jAED"},
    {"base_currency": "jAED","rec_currency": "ETH"}]}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencySerializer

    def get(self, request):
        currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True)

        data = {"success": True, "currencies": []}
        for pair in currency_pairs:
            if pair.is_buyable:
                data["currencies"].append({"base_currency": pair.base_currency.display_name,
                             "rec_currency": pair.reciprocal_currency.display_name})
            if pair.is_sellable:
                data["currencies"].append({"base_currency": pair.reciprocal_currency.display_name,
                             "rec_currency": pair.base_currency.display_name})
        return Response(data)


class CurrencyRateView(GenericAPIView):
    """
    post:
    Get currency rate info.
    Response example:

    ```
    {"success":true,
    "uuid":"eb5c4978-c70a-4572-9f58-72250fce6b3f",
    "rate":1799.0, "base_amount":1.0, "rec_amount":1799.0}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencyRateSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = CurrencyRateSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            is_reverse_operation = False
            currency_pair = CurrencyPair.objects.filter(base_currency__display_name__iexact=serializer.validated_data['base_currency'],
                                                         reciprocal_currency__display_name__iexact=serializer.validated_data['rec_currency']) \
                .first()

            if not currency_pair:
                currency_pair = CurrencyPair.objects.filter(
                    base_currency__display_name__iexact=serializer.validated_data['rec_currency'],
                    reciprocal_currency__display_name__iexact=serializer.validated_data['base_currency']
                ).first()
                is_reverse_operation = True

            if not currency_pair:
                return Response({'success': False, 'error': "Currency does not exists."}, status=400)

            currency_pair_rate = currency_pair.currency_pair_rates.latest('created_at')

            if not currency_pair_rate:
                return Response({'success': False, 'error': "Currency price does not exists."}, status=400)

            currency_pair_rate_price = currency_pair_rate.sell_price if is_reverse_operation else currency_pair_rate.buy_price
            if is_reverse_operation:
                currency_pair_rate_price = 1.0 / currency_pair_rate_price

            base_amount = 0.0
            rec_amount = 0.0

            if serializer.validated_data.get('base_amount'):
                base_amount = serializer.validated_data['base_amount']
                rec_amount = base_amount * currency_pair_rate_price

            if serializer.validated_data.get('rec_amount'):
                rec_amount = serializer.validated_data['rec_amount']
                base_amount = rec_amount / currency_pair_rate_price

            data = {"success": True,
                    "uuid": currency_pair_rate.id,
                    "rate": currency_pair_rate_price,
                    "rec_amount": rec_amount,
                    "base_amount": base_amount}
            return Response(data)


class CurrencyRatesView(GenericAPIView):
    """
    Get currency-pairs rates.

    Response example:

    ```
    {"success":true,"currencies":[{"base_currency":"ETH","rec_currency":"jAED","rate_buy":1799.0,"rate_sell":1798.0}]}
    ```
    """

    permission_classes = (permissions.AllowAny,)
    serializer_class = OpenCurrencyRateSerializer

    @cache_response(20)
    def get(self, request):
        currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True)
        currencies = []
        for pair in currency_pairs:
            last_rate = pair.currency_pair_rates.latest('created_at')

            rate_buy = 0.0
            rate_sell = 0.0

            if last_rate:
                rate_buy = last_rate.buy_price
                rate_sell = last_rate.sell_price

            currencies.append({"base_currency": pair.base_currency.display_name,
                               "rec_currency": pair.reciprocal_currency.display_name,
                               "rate_buy": rate_buy,
                               "rate_sell": rate_sell})

        data = {'success': True,
                'currencies': currencies}
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

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

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
    {"success":true,
     "addresses":
     [{"address": "0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2","type": "eth","is_verified": true}]
     }
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
     "uuid":"a357e783-bcad-4d1e-a6d1-b0e80aec31e0"}
    ```

    or

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = AddressSerializer
    parser_classes = (JSONParser,)

    @classmethod
    def get_account_addresses(cls, request):
        addresses_qs = Address.objects.filter(user=request.user, is_removed=False)
        addresses = AddressesSerializer(addresses_qs, many=True).data
        response_data = {'success': True, 'addresses':addresses}
        return Response(response_data)

    def get(self, request):
        return self.get_account_addresses(request)

    def post(self, request):
        if Account.is_user_email_confirmed(request.user) is False:
            return Response({"success": False, "error":"Please confirm the e-mail before submitting the own addresses"}, status=400)

        if not request.user.account.is_identity_verified:
            return Response({"success": False, "error":"Personal data is not verified yet."}, status=400)

        addresses = Address.objects.filter(user=request.user, is_removed=False)
        if len(addresses) >= LOGIC__MAX_ADDRESSES_NUM:
            return Response({"success": False, "error": "Too many addresses."}, status=400)

        serializer = self.serializer_class(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save(request.user)
            return Response(serializer.validated_data)

        return Response({"success": False, "error": serializer.errors}, status=400)


class RemoveAddressView(GenericAPIView):
    """
    Remove address for account.

    post:
    Remove an address for current user.

    Response example:

    ```
    {"success":true,
     "addresses":
     [{"address": "0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2","type": "eth","is_verified": true}]
     }
    ```

    or

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = RemoveAddressSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        if Account.is_user_email_confirmed(request.user) is False:
            return Response({"success": False, "error":"Please confirm the e-mail"}, status=400)

        if not request.user.account.is_identity_verified:
            return Response({"success": False, "error":"Personal data is not verified yet."}, status=400)

        serializer = RemoveAddressSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()

        return AddressView.get_account_addresses(request)


class CustomUserDetailsView(APIView):
    """
    Reads UserModel fields
    Accepts GET method.

    * Requires token authentication.

    Default display fields: username, email
    Read-only fields: username, email

    Returns UserModel fields.
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({'success':True, 'username':request.user.username, 'email':request.user.email})


@docstring_parameter(get_status_class_members(ApplicationStatus))
class ApplicationView(GenericAPIView):
    """
    View get/set exchange application.

    * Requires token authentication.

    get:
    Returns an exchange history for current user.

    Response example:

    ```
    {{"success":true, "applications":
    [{{
    "app_uuid": "6242cd54-0616-48d8-b1d4-d1ed99116b1b",
    "created_at": "2018-05-22T16:08:21.132030Z",
    "expired_at": "2018-05-22T16:38:21.132030Z",
    "incoming_tx_id": "0x1234543431",
    "outgoing_tx_id": "",
    "incoming_tx_value": 2,
    "outgoing_tx_value": 0,
    "source_address": "0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2",
    "exchanger_address": "0x55555555",
    "base_currency": "ETH",
    "base_amount": 1,
    "reciprocal_currency": "jAED",
    "reciprocal_amount": 1799,
    "rate": 1799,
    "is_active": true,
    "status": "converting"
    }}]}}
    ```

    **Statuses**

    {0}

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
        return Response({"success": True, "application": applications})

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success":True, "app_uuid": serializer.validated_data['application_id']})
        else:
            return Response({"success": False, "error": serializer.errors})


@docstring_parameter(get_status_class_members(ApplicationStatus))
class ApplicationDetailView(GenericAPIView):
    """
    View get exchange application.

    get:
    Returns application detail.

    * Requires token authentication.

    Response example:

    ```
    {{"success":true, "application":{{
    "app_uuid": "6242cd54-0616-48d8-b1d4-d1ed99116b1b",
    "created_at": "2018-05-22T16:08:21.132030Z",
    "expired_at": "2018-05-22T16:38:21.132030Z",
    "incoming_tx_id": "0x1234543431",
    "outgoing_tx_id": "",
    "incoming_tx_value": 2,
    "outgoing_tx_value": 0,
    "source_address": "0xc1fd943329dac131f6f8ab3c0290e02b7651e2f2",
    "exchanger_address": "0x55555555",
    "base_currency": "ETH",
    "base_amount": 1,
    "reciprocal_currency": "jAED",
    "reciprocal_amount": 1799,
    "rate": 1799,
    "is_active": true,
    "status": "converting"
    }}}}
    ```

    **Statuses**

    {0}
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, uuid=None):
        try:
            app = Application.objects.filter(user=request.user, id=uuid).first()
        except:
            return Response({"success": False, "error": "no such application"}, status=400)
        application = ApplicationsSerializer(app, many=False).data
        return Response({"success": True, "application": application})


class ApplicationConfirmView(GenericAPIView):
    """
    Confirm exchange application if incoming transaction amount less than exchange amount
    Accepts POST method.

    post:
    Changes status of application to perform exchange operation <mark>"converting"</mark>.
    It might be possible if application status is <mark>"confirming"</mark>

    Returns the success/fail message.

    Response example:

    ```
    {"success":true}
    ```

    or

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

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
    Changes status of application to cancel exchange operation and refund <mark>"refunding"</mark>.
    It might be possible if application status is <mark>"confirming"</mark>

    Returns the success/fail message.

    Response example:

    ```
    {"success":true}
    ```

    or

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

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


class ApplicationCancelView(GenericAPIView):
    """
    Cancel exchange application by user.
    Accepts POST method.

    post:
    Changes status of application to cancel exchange operation by user.
    It might be possible if application status is <mark>"created"</mark>

    Returns the success/fail message.

    Response example:

    ```
    {"success":true}
    ```

    or

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationCancelSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success":True})

        return Response({"success":False, "error":{serializer.errors}}, status=400)


class ApplicationFinishView(GenericAPIView):
    """
    Finish exchange application.
    Accepts POST method.

    post:
    Changes status of application to finish exchange operation.
    It might be possible if application status is <mark>"converted","refunded"</mark>

    Returns the success/fail message.

    Response example:

    ```
    {"success":true}
    ```

    or

    ```{"success": false, "error": "error description"}```

    ```{"success": false, "errors": {"field_name":"error_description"}}```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ApplicationFinishSerializer
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
        serializer_data['success'] = True
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

        try:
            confirmation = self.get_object()
        except:
            return Response({'success': False, 'error': 'failed'}, status=404)

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


class CustomLoginView(LoginView):
    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: username, password
    Return the REST Framework Token Object's key.
    """
    def get_response(self):
        response = super().get_response()
        response.data['success'] = True

        return response
