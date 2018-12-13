import logging
import inspect
import sys
from allauth.account import app_settings as allauth_settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth import logout as django_logout
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.utils.translation import ugettext_lazy as _
from rest_framework_extensions.cache.decorators import cache_response
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework import status
from rest_auth.registration.views import RegisterView as RestAuthRegisterView, VerifyEmailView
from django.db import transaction
from rest_auth.app_settings import (
    TokenSerializer,
    JWTSerializer
)
from rest_auth.views import (
    PasswordChangeView, PasswordResetView, PasswordResetConfirmView, LogoutView, LoginView
)
from allauth.account.utils import send_email_confirmation
from zxcvbn_password import zxcvbn

from jcash.api.models import (
    Address,
    Account,
    AccountStatus,
    AccountType,
    CurrencyPair,
    Application,
    ApplicationStatus,
    ApplicationCancelReason,
    Country,
    CountryType,
    Personal,
    Corporate,
    CustomerStatus,
    KycSteps,
    get_email_templates,
    Currency,
)
from jcash.api.serializers import (
    AccountSerializer,
    AddressesSerializer,
    AddressSerializer,
    RemoveAddressSerializer,
    AddressVerifySerializer,
    AccountInitSerializer,
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
    PersonalContactInfoSerializer,
    PersonalAddressSerializer,
    PersonalIncomeInfoSerializer,
    PersonalDocumentsSerializer,
    CorporateCompanyInfoSerializer,
    CorporateAddressSerializer,
    CorporateIncomeInfoSerializer,
    CorporateContactInfoSerializer,
    CorporateDocumentsSerializer,
    CountriesSerializer,
    CorporateSerializer,
    PersonalSerializer,
    CustomersSerializer,
    CheckTokenSerializer,
    ValidatePasswordSerializer,
    VideoVerificationSerializer,
    SendEmailSerializer,
    ConfirmationsSerializer,
)
from jcash.commonutils import currencyrates, math, notify, eth_contracts
from jcash.commonutils.db_utils import require_lock
from jcash.settings import LOGIC__MAX_ADDRESSES_NUM, FRONTEND_URL, LOGIC__VIDEO_VERIFY_TEXT
from jcash.appprocessor.commands import proof_of_solvency
from jcash.api.pagination import ApplicationPageNumberPagination


logger = logging.getLogger(__name__)


def get_status_class_members(obj):
    def get_description(obj, attr):
        return "<mark>{}</mark> - {}".format(getattr(getattr(obj,attr), 'name'),
                                getattr(getattr(obj,attr), 'description'))

    _obj = obj()

    return ", ".join([get_description(_obj, attr) for attr in dir(_obj) \
                      if not callable(getattr(_obj, attr)) and not attr.startswith("__") and \
                      (not hasattr(getattr(obj, attr), 'hide') or not getattr(obj, attr).hide)])


def docstring_parameter(*sub):
    def dec(obj):
        obj.__doc__ = obj.__doc__.format(*sub)
        return obj
    return dec


@docstring_parameter(get_status_class_members(AccountStatus))
class AccountView(GenericAPIView):
    """
    get:
    Returns account info for current user.

    Response example

    ```
    {{"success": true,
     "username": "ivan_ivanov@example.com",
     "firstname": "Ivan",
     "lastname": "Ivanov",
     "middlename": null,
     "birthday": "2017-01-01",
     "nationality": "Zambia",
     "residency": "Zambia",
     "is_email_confirmed":true,
     "status": "verified",
    }}
    ```

    **Account Statuses**

    {0}

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

    @classmethod
    def ensure_account(cls, request):
        try:
            account = request.user.account
        except ObjectDoesNotExist:
            account = Account.objects.create(user=request.user)
        return account

    def get(self, request):
        account = self.ensure_account(request)
        self.action = request.method.lower()
        account_serializer = AccountSerializer(account)

        return Response(account_serializer.data)


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
            logger.info('Resend email confirmation failed {}'.format(request.user.username))
            return Response({'success': False, 'error': [_('Resend email confirmation failed')]}, status=400)
        logger.info('Resend email confirmation succeeded {}'.format(request.user.username))
        return Response({'success': True})


class FeeJntView(APIView):
    """
    Get current exchange fee in JNT.

    Response example:

    ```
    {"success":true, "value": 50.0} |
    {"success":false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)

    def get(self, request):
        try:
            eth_currency = Currency.objects.get(Q(symbol__icontains='eth') &
                                                ~Q(is_disabled=True))
            fee = eth_contracts.feeJNT(eth_currency.abi,
                                       eth_currency.exchanger_address)

            return Response({'success': True, 'value': fee})
        except:
            return Response({'success': False, 'error': 'Fee does not exist.'}, status=400)

        return Response(data)


class CurrencyView(APIView):
    """
    Get available currencies on the platform.

    Response example:

    ```
    {"success":true,"currencies":[
    {"base_currency":"ETH","rec_currency":"jAED","round_digits":4,"min_limit":1.0,"max_limit":999.0},
    {"base_currency":"jAED","rec_currency":"ETH","round_digits":2,"min_limit":1000.0,"max_limit":999999.0}
    ]}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CurrencySerializer

    def get(self, request):
        currency_pairs = CurrencyPair.objects.filter(Q(is_exchangeable=True) &
                                                     Q(base_currency__is_disabled=False) &
                                                     Q(reciprocal_currency__is_disabled=False))

        data = {"success": True, "currencies": []}
        for pair in currency_pairs:
            if pair.is_buyable:
                data["currencies"].append({"base_currency": pair.base_currency.display_name,
                                           "rec_currency": pair.reciprocal_currency.display_name,
                                           "round_digits": pair.base_currency.round_digits,
                                           "min_limit": pair.base_currency.min_limit,
                                           "max_limit": pair.base_currency.max_limit})
            if pair.is_sellable:
                data["currencies"].append({"base_currency": pair.reciprocal_currency.display_name,
                                           "rec_currency": pair.base_currency.display_name,
                                           "round_digits": pair.reciprocal_currency.round_digits,
                                           "min_limit": pair.reciprocal_currency.min_limit,
                                           "max_limit": pair.reciprocal_currency.max_limit})
        return Response(data)


class CurrencyRateView(GenericAPIView):
    """
    post:
    Get currency rate info.
    Response example:

    ```
    {"success":true,
    "uuid":"eb5c4978-c70a-4572-9f58-72250fce6b3f",
    "is_reverse": false,
    "rate":1799.0, "base_amount":1.0, "rec_amount":1799.0, "round_digits":2}
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
            currency_pair = CurrencyPair.objects.filter(Q(base_currency__display_name__iexact=serializer.validated_data['base_currency']) &
                                                        Q(reciprocal_currency__display_name__iexact=serializer.validated_data['rec_currency']),
                                                        Q(base_currency__is_disabled=False) &
                                                        Q(reciprocal_currency__is_disabled=False)) \
                                                .first()

            if not currency_pair:
                currency_pair = CurrencyPair.objects.filter(
                    Q(base_currency__display_name__iexact=serializer.validated_data['rec_currency']) &
                    Q(reciprocal_currency__display_name__iexact=serializer.validated_data['base_currency']) &
                    Q(base_currency__is_disabled=False) &
                    Q(reciprocal_currency__is_disabled=False)
                ).first()
                is_reverse_operation = True

            if not currency_pair:
                return Response({'success': False, 'error': "Currency does not exists."}, status=400)

            currency_pair_rate = None

            if hasattr(currency_pair, 'currency_pair_rates') and currency_pair.currency_pair_rates.count() > 0:
                currency_pair_rate = currency_pair.currency_pair_rates.latest('created_at')

            if not currency_pair_rate:
                return Response({'success': False, 'error': "Currency price does not exists."}, status=400)

            currency_pair_rate_price = currencyrates.get_currency_pair_rate(currency_pair_rate,
                                                                            is_reverse_operation)
            if is_reverse_operation:
                currency_pair_rate_price = math.calc_reverse_rate(currency_pair_rate_price)

            rec_currency = currency_pair.base_currency if is_reverse_operation else \
                currency_pair.reciprocal_currency

            rec_currency_round_digits = rec_currency.round_digits
            base_amount = 0.0
            rec_amount = 0.0

            if serializer.validated_data.get('base_amount'):
                base_amount = math.round_amount(serializer.validated_data['base_amount'],
                                                currency_pair,
                                                is_reverse_operation,
                                                True)

                rec_amount = math.round_amount(math.calc_reciprocal_amount(base_amount, currency_pair_rate_price),
                                               currency_pair,
                                               is_reverse_operation,
                                               False)

            if serializer.validated_data.get('rec_amount'):
                rec_amount = math.round_amount(serializer.validated_data['rec_amount'],
                                               currency_pair,
                                               is_reverse_operation,
                                               False)

                base_amount = math.round_amount(math.calc_base_amount(rec_amount, currency_pair_rate_price),
                                                currency_pair,
                                                is_reverse_operation,
                                                True)

            data = {"success": True,
                    "uuid": currency_pair_rate.id,
                    "rate": math.calc_reverse_rate(currency_pair_rate_price) if is_reverse_operation else \
                        currency_pair_rate_price,
                    "rec_amount": rec_amount,
                    "base_amount": base_amount,
                    "round_digits": rec_currency_round_digits,
                    "is_reverse": is_reverse_operation}
            return Response(data)


class CurrencyRatesView(GenericAPIView):
    """
    Get currency-pairs rates.

    Response example:

    ```
    {"success":true,"currencies":[{"id":1,"base_currency":"ETH","rec_currency":"jAED","rate_buy":1799.0,"rate_sell":1798.0}]}
    ```
    """

    permission_classes = (permissions.AllowAny,)
    serializer_class = OpenCurrencyRateSerializer

    @cache_response(20)
    def get(self, request):
        currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True).order_by('sort_id')
        currencies = []
        for pair in currency_pairs:
            last_rate = None
            if hasattr(pair, 'currency_pair_rates') and \
                    pair.currency_pair_rates.count() > 0:
                last_rate = pair.currency_pair_rates.latest('created_at')

            rate_buy = 0.0
            rate_sell = 0.0

            if last_rate:
                rate_buy = last_rate.buy_price
                rate_sell = last_rate.sell_price

            currencies.append({"id": pair.sort_id,
                               "base_currency": pair.base_currency.display_name,
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
        is_have_exchange_rights, error = Account.check_exchange_rights(request.user)
        if not is_have_exchange_rights:
            return Response({"success": False, "error": error}, status=400)

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
        is_have_exchange_rights, error = Account.check_exchange_rights(request.user)
        if not is_have_exchange_rights:
            return Response({"success": False, "error": error}, status=400)

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


@docstring_parameter(get_status_class_members(ApplicationStatus),
                     get_status_class_members(ApplicationCancelReason))
class ApplicationView(GenericAPIView):
    """
    View get/set exchange application.

    * Requires token authentication.

    get:
    Returns an exchange history for current user.

    Response example:

    ```
    {{"success":true,
      "count": 1,
      "next": "http://localhost:8000/api/application/?page=2",
      "previous": null,
      "applications":
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
    "token_address": "0x6666666",
    "base_currency": "ETH",
    "base_amount": 1,
    "reciprocal_currency": "jAED",
    "reciprocal_amount": 1799,
    "reciprocal_amount_actual": 3598,
    "rate": 1799,
    "is_active": true,
    "is_reverse": false,
    "status": "converting",
    "reason": "",
    "round_digits": 2,
    "fee": 50.0
    }}]}}
    ```

    **Statuses**

    {0}


    **Reasons**

    {1}

    post:
    Create a new exchange application for current user.

    Response example:

    ```{{"success":true, "app_uuid": "6242cd54-0616-48d8-b1d4-d1ed99116b1b"]}}```

    or

    ```{{"success":false, "error": "error_description"}}```

    ```{{"success":false, "errors": {{"jnt": ["not_enough_jnt"]}}}}```


    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    parser_classes = (JSONParser,)
    serializer_class = ApplicationSerializer
    permission_classes = (IsAuthenticated,)
    pagination_class = ApplicationPageNumberPagination

    def get(self, request):
        applications_qs = Application.objects.filter(user=self.request.user).order_by('-created_at')

        paginator = self.pagination_class()
        page = paginator.paginate_queryset(applications_qs, request)

        serializer = ApplicationsSerializer(page, many=True)
        pagination_data = dict(paginator.get_paginated_response(serializer.data).data)
        pagination_data['success'] = True
        pagination_data['applications'] = pagination_data.pop('results')

        return Response(pagination_data)

    @transaction.atomic
    @require_lock(Application, 'ROW SHARE')
    def post(self, request):
        is_have_exchange_rights, error = Account.check_exchange_rights(request.user)
        if not is_have_exchange_rights:
            return Response({"success": False, "error": error}, status=400)

        serializer = self.serializer_class(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success":True, "app_uuid": serializer.validated_data['application_id']})
        else:
            return Response({"success": False, "error": serializer.errors})


@docstring_parameter(get_status_class_members(ApplicationStatus),
                     get_status_class_members(ApplicationCancelReason))
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
    "token_address": "0x6666666",
    "base_currency": "ETH",
    "base_amount": 1,
    "reciprocal_currency": "jAED",
    "reciprocal_amount": 1799,
    "reciprocal_amount_actual": 3598,
    "rate": 1799,
    "is_active": true,
    "is_reverse": false,
    "status": "converting",
    "reason": "",
    "round_digits": 2
    }}}}
    ```

    **Statuses**

    {0}

    **Reasons**

    {1}
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


class VideoVerificationView(GenericAPIView):
    """
    get:
    Returns video verification details.

    Response example:

    ```{{"success":true, "message":"I, John Smith, ..."}}```

    or

    ```{{"success":false, "error": "error_description"}}```

    post:
    Set Ziggeo video ID.

    Response example:

    ```{{"success":true}}```

    or

    ```{{"success":false, "error": "error_description"}}```
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = VideoVerificationSerializer
    parser_classes = (JSONParser,)
    customer_type = None

    def get(self, request):
        account = AccountView.ensure_account(request)

        customer = None

        if self.customer_type == AccountType.personal and hasattr(account, Account.rel_personal):
            customer = account.personal

        if self.customer_type == AccountType.corporate and hasattr(account, Account.rel_corporate):
            customer = account.corporate

        if not customer:
            return Response({'success': False, 'error': 'customer does not exist'})

        video_message = LOGIC__VIDEO_VERIFY_TEXT.format(
            customer.firstname if isinstance(customer, Personal) else customer.contact_firstname,
            customer.lastname if isinstance(customer, Personal) else customer.contact_lastname,
            customer.country if isinstance(customer, Personal) else customer.contact_residency)

        return Response({"success": True, "message": video_message})

    def post(self, request):
        serializer = self.serializer_class(data=request.data,
                                           context={'user': request.user, 'customer_type': self.customer_type})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success": True})


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
        is_have_exchange_rights, error = Account.check_exchange_rights(request.user)
        if not is_have_exchange_rights:
            return Response({"success": False, "error": error}, status=400)

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
        is_have_exchange_rights, error = Account.check_exchange_rights(request.user)
        if not is_have_exchange_rights:
            return Response({"success": False, "error": error}, status=400)

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
        is_have_exchange_rights, error = Account.check_exchange_rights(request.user)
        if not is_have_exchange_rights:
            return Response({"success": False, "error": error}, status=400)

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
        notify.send_email_few_steps_away(confirmation.email_address.user.email \
                                             if confirmation.email_address.user else None,
                                         FRONTEND_URL,
                                         confirmation.email_address.user.pk \
                                             if confirmation.email_address.user else None)
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


class PersonalContactInfoView(GenericAPIView):
    """
    get:
    Get contact information.

    Response example:

    ```
    {"success": true, "firstname": "", "lastname": "", "middlename": "", "nationality": "",
    "birthday": "", "phone": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates personal contact information.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = PersonalContactInfoSerializer
    parser_classes = (JSONParser,)

    @classmethod
    def ensure_personal(cls, account):
        try:
            personal = account.personal
        except ObjectDoesNotExist:
            personal = Personal.objects.create(account=account)
        return personal

    def get(self, request):
        account = AccountView.ensure_account(request)

        if hasattr(account, Account.rel_personal):
            serializer = PersonalSerializer(account.personal, context={'status': ''})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            personal = self.ensure_personal(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(personal)
        return Response({'success': True})


class PersonalAddressView(GenericAPIView):
    """
    get:
    Get address information.

    Response example:

    ```
    {"success": true, "country": "", "street": "", "apartment": "", "city": "", "postcode": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates personal residential / address.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = PersonalAddressSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        account = AccountView.ensure_account(request)

        if hasattr(account, Account.rel_personal):
            serializer = PersonalSerializer(account.personal, context={'status': str(CustomerStatus.address)})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            personal = PersonalContactInfoView.ensure_personal(account)
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(personal)
            return Response({'success': True})


class PersonalIncomeInfoView(GenericAPIView):
    """
    get:
    Get income information.

    Response example:

    ```
    {"success": true, "profession": "", "income_source": "", "assets_origin": "", "jcash_use": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates personal income information.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = PersonalIncomeInfoSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        account = AccountView.ensure_account(request)

        if hasattr(account, Account.rel_personal):
            serializer = PersonalSerializer(account.personal, context={'status': str(CustomerStatus.income_info)})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            personal = PersonalContactInfoView.ensure_personal(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(personal)
        return Response({'success': True})


class PersonalDocumentsView(GenericAPIView):
    """
    post:
    Uploads personal documents.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = PersonalDocumentsSerializer
    parser_classes = (MultiPartParser,)

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            personal = PersonalContactInfoView.ensure_personal(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(personal)
        return Response({'success': True})


class CorporateCompanyInfoView(GenericAPIView):
    """
    get:
    Get company information.

    Response example:

    ```
    {"success": true, "name": "", "domicile_country": "", "business_phone": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates company information.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CorporateCompanyInfoSerializer
    parser_classes = (JSONParser,)

    @classmethod
    def ensure_corporate(cls, account):
        try:
            corporate = account.corporate
        except ObjectDoesNotExist:
            corporate = Corporate.objects.create(account=account)
        return corporate

    def get(self, request):
        account = AccountView.ensure_account(request)
        if hasattr(account, Account.rel_corporate):
            serializer = CorporateSerializer(account.corporate, context={'status': ''})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            corporate = self.ensure_corporate(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(corporate)
        return Response({'success': True})


class CorporateAddressView(GenericAPIView):
    """
    get:
    Get business information.

    Response example:

    ```
    {"success": true, "country": "", "street": "", "apartment": "", "city": "", "postcode": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates business address.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CorporateAddressSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        account = AccountView.ensure_account(request)

        if hasattr(account, Account.rel_corporate):
            serializer = CorporateSerializer(account.corporate, context={'status': str(CustomerStatus.business_address)})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            corporate = CorporateCompanyInfoView.ensure_corporate(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(corporate)
        return Response({'success': True})


class CorporateIncomeInfoView(GenericAPIView):
    """
    get:
    Get income information.

    Response example:

    ```
    {"success": true, "industry": "", "assets_origin": "", "currency_nature": "",
    "assets_origin_description": "", "jcash_use": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates company income information.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CorporateIncomeInfoSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        account = AccountView.ensure_account(request)

        if hasattr(account, Account.rel_corporate):
            serializer = CorporateSerializer(account.corporate, context={'status': str(CustomerStatus.income_info)})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            corporate = CorporateCompanyInfoView.ensure_corporate(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(corporate)
        return Response({'success': True})


class CorporateContactInfoView(GenericAPIView):
    """
    get:
    Get primary contact information.

    Response example:

    ```
    {"success": true, "contact_firstname": "", "contact_lastname": "", "contact_middlename": "",
    "contact_birthday": "", "contact_nationality": "",
    "contact_residency": "", "contact_phon": "", "contact_email": "", "contact_street": "",
    "contact_apartment": "", "contact_city": "", "contact_postcode": ""} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates company's primary contact information.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CorporateContactInfoSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        account = AccountView.ensure_account(request)

        if hasattr(account, Account.rel_corporate):
            serializer = CorporateSerializer(account.corporate, context={'status': str(CustomerStatus.primary_contact)})
            return Response(serializer.data)
        return Response({'success': False, 'error': 'customer does not exist'})

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            corporate = CorporateCompanyInfoView.ensure_corporate(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(corporate)
        return Response({'success': True})


class CorporateDocumentsView(GenericAPIView):
    """
    post:
    Uploads company documents.

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CorporateDocumentsSerializer
    parser_classes = (MultiPartParser,)

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)
        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            corporate = CorporateCompanyInfoView.ensure_corporate(account)

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(corporate)
        return Response({'success': True})


class ResidentialCountriesView(GenericAPIView):
    """
    get:
    Get residential countries list.

    Response example:

    ```
    {"success": true,"countries": ["Germany","Switzerland","United Kingdom"]}
    ```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CountriesSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        countries_qs = Country.objects.filter(type=CountryType.residential, is_removed=False)
        countries = CountriesSerializer(countries_qs, many=True).data
        response_data = {'success': True, 'countries': countries}
        return Response(response_data)


class CitizenshipCountriesView(GenericAPIView):
    """
    get:
    Get citizenship countries list.

    Response example:

    ```
    {"success": true, "countries": ["Sudan","Italy", "Ethiopia"]}
    ```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CountriesSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        countries_qs = Country.objects.filter(type=CountryType.citizenship, is_removed=False)
        countries = CountriesSerializer(countries_qs, many=True).data
        response_data = {'success': True, 'countries': countries}
        return Response(response_data)


class CheckTokenView(GenericAPIView):
    """
    post:
    Check token

    Response example:

    ```
    {"success": true} |
    {"success": false}

    ```
    """
    permission_classes = (permissions.AllowAny,)
    serializer_class = CheckTokenSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response({'success': True})
        else:
            return Response({'success': False}, status=400)


class ValidatePasswordView(GenericAPIView):
    """
    post:
    Validate password

    Response example:

    ```
    {"success": true} |
    {"success": false, "error": "error_description"} |
    {"success": false, "errors": {object}}
    ```
    """
    permission_classes = (permissions.AllowAny,)
    serializer_class = ValidatePasswordSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        try:
            score = zxcvbn(request.data.get('password', ''))['score']
        except IndexError:
            score = 0
        if serializer.is_valid(raise_exception=False):
            return Response({'success': True, 'score': score})
        else:
            return Response({'success': False, 'score': score, 'error': _('Password is too weak.')}, status=400)


@docstring_parameter(get_status_class_members(KycSteps))
class CustomersView(GenericAPIView):
    """
    get:
    Get customers list.

    Response example:

    ```
    {{"success": true, "customers": [{{ "type": "personal",
                     "uuid": "f9229b1b-f859-4cc9-b8ef-501238ca721b",
                     "kyc_step": 0}}]}}
    ```

    **KYC Steps**

    {0}

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = CountriesSerializer
    parser_classes = (JSONParser,)

    def get(self, request):
        account = AccountView.ensure_account(request)
        customers = []

        if hasattr(account, account.rel_personal):
            customers.append(account.personal)

        if hasattr(account, account.rel_corporate):
            customers.append(account.corporate)

        customer_serializer = CustomersSerializer(customers, many=True)
        response_data = {"success": True, "customers": customer_serializer.data}

        return Response(response_data)


class ProofOfSolvencyView(GenericAPIView):
    """
    get:
    Proof of solvency.

    Response example:

    ```
    {
      "success": true,
      "data": {
        "summary": {
          "jnt_price": 0.1,
          "solvency_requirement": 202159,
          "proof_of_solvency": 1250000,
          "liquidity": 6.1832
        },
        "crydrs": {
          "jUSD": {
            "minted": 1000000,
            "circulating": 11257.12,
            "jnt_requirement": 114285.48
          },
          "jEUR": {
            "minted": 400000,
            "circulating": 12.11,
            "jnt_requirement": 122.96
          },
          "jKRW": {
            "minted": 350000000,
            "circulating": 4512.24,
            "jnt_requirement": 45809.54
          },
          "jGBP": {
            "minted": 200000,
            "circulating": 4131.20,
            "jnt_requirement": 41941.12
          }
        },
        "liquidity_providers": [{
          "entity": "JNT Commercial Brokers",
          "jnt_pledge": 1000000,
          "current_fee_share": 0.8,
          "fees_collected": 100
        }, {
          "entity": "JNT Commercial Brokers #2",
          "jnt_pledge": 250000,
          "current_fee_share": 0.2,
          "fees_collected": 230
        }]
      }
    }
    ```

    """
    permission_classes = (permissions.AllowAny,)
    parser_classes = (JSONParser,)

    def get(self, request):
        response_data = proof_of_solvency()
        response_data.update({'success': True})

        return Response(response_data)


class EmailTemplatesView(GenericAPIView):
    """
    get:
    Get email templates

    Response example:

    ```
    {"success": true, templates: [{'name':'password_reset','parameters':['activate_url','reason']}]}

    or

    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAdminUser,)
    parser_classes = (JSONParser,)

    def get(self, request):
        templates = get_email_templates()
        response_data = {'success': True, 'templates': templates}
        return Response(response_data)


class SendEmailView(GenericAPIView):
    """
    post:
    Send email

    Response example:

    ```
    {"success": true} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAdminUser,)
    serializer_class = SendEmailSerializer
    parser_classes = (JSONParser,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'success': True})


class ConfirmationsView(GenericAPIView):
    """
    get:
    Get confirmations.

    Response example:

    ```
    {"success": true, "is_terms_agreed": false, "is_not_political": false, "is_ultimate_owner": false,
     "is_information_confirmed": false} |
    {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.

    post:
    Updates confirmations

    Response example:

    ```
    {"success": true} | {"success": false, "error": "error_description"}
    ```

    * Requires token authentication.
    """

    authentication_classes = (authentication.TokenAuthentication,)
    serializer_class = ConfirmationsSerializer
    parser_classes = (JSONParser,)
    customer_type = None

    def get(self, request):
        account = AccountView.ensure_account(request)

        customer = None

        if self.customer_type == AccountType.personal and hasattr(account, Account.rel_personal):
            customer = account.personal

        if self.customer_type == AccountType.corporate and hasattr(account, Account.rel_corporate):
            customer = account.corporate

        if not customer:
            return Response({'success': False, 'error': 'customer does not exist'})
        else:
            return Response(
                {
                    'success': True,
                    "is_terms_agreed": customer.is_terms_agreed,
                    "is_not_political": customer.is_not_political,
                    "is_ultimate_owner": customer.is_ultimate_owner,
                    "is_information_confirmed": customer.is_information_confirmed
                }
            )

    def post(self, request):
        is_have_kyc_rights, error = Account.check_kyc_rights(request.user)

        with transaction.atomic():
            account = AccountView.ensure_account(request)
            if self.customer_type == AccountType.personal:
                PersonalContactInfoView.ensure_personal(account)
            elif self.customer_type == AccountType.corporate:
                CorporateCompanyInfoView.ensure_corporate(account)

        if not is_have_kyc_rights:
            return Response({"success": False, "error": error}, status=400)

        serializer = self.serializer_class(data=request.data,
                                           context={'user': request.user, 'customer_type': self.customer_type})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'success': True})
