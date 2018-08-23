import logging
from datetime import date, datetime, timedelta
from dateutil.tz import tzlocal

from django.db import transaction
from django import forms
from django.db.models import Sum
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, password_validation
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import ugettext_lazy as _
from django.contrib.sites.models import Site
from django.core.validators import MinValueValidator
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.utils import timezone, dateformat
from django.utils.encoding import force_text
from allauth.account import app_settings as allauth_settings
from allauth.utils import email_address_exists
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from rest_auth.serializers import PasswordResetSerializer, PasswordResetForm
from rest_framework import serializers, exceptions
from rest_framework.fields import CurrentUserDefault
import requests

from jcash.api.fields import CustomDateField
from jcash.api.models import (
    Address, Account, Document,
    DocumentHelper, AddressVerify, Application, CurrencyPair, ApplicationStatus,
    IncomingTransaction, Exchange, Refund, AccountStatus, Country,
    Personal, AccountType, PersonalFieldLength, DocumentGroup, DocumentType,
    CorporateFieldLength, Corporate, CustomerStatus, DocumentVerification,
    ApplicationCancelReason, ExchangeFee,
)
from jcash.api.validators import BirthdayValidator
from jcash.commonutils import (
    eth_sign,
    eth_address,
    eth_contracts,
    math,
    currencyrates,
    ga_integration,
    exchange_utils as utils
)
from jcash.commonutils import notify
from jcash.settings import (
    FRONTEND_URL,
    LOGIC__EXPIRATION_LIMIT_SEC,
    LOGIC__OUT_OF_DATE_PRICE_SEC,
    LOGIC__ADDRESS_VERIFY_TEXT,
)


logger = logging.getLogger(__name__)

RECAPTCHA_API_URL = 'https://www.google.com/recaptcha/api/siteverify'

class CaptchaHelper():
    @classmethod
    def validate_captcha(cls, captcha_token):
        if settings.RECAPTCHA_ENABLED is not True:
            return True
        try:
            r = requests.post(
                RECAPTCHA_API_URL,
                {
                    'secret': settings.RECAPTCHA_PRIVATE_KEY,
                    'response': captcha_token
                },
                timeout=5
            )
            r.raise_for_status()
        except requests.RequestException as e:
            raise serializers.ValidationError(
                _('Connection to reCaptcha server failed. Please try again')
            )

        json_response = r.json()

        if bool(json_response['success']):
            return True
        else:
            if 'error-codes' in json_response:
                if 'missing-input-secret' in json_response['error-codes'] or \
                        'invalid-input-secret' in json_response['error-codes']:

                    logger.error('Invalid reCaptcha secret key detected {}'.format(settings.RECAPTCHA_PRIVATE_KEY))
                    raise serializers.ValidationError(
                        _('Connection to reCaptcha server failed')
                    )
                else:
                    raise serializers.ValidationError(
                        _('reCaptcha invalid or expired, try again')
                    )
            else:
                logger.error('No error-codes received from Google reCaptcha server')
                raise serializers.ValidationError(
                    _('reCaptcha response from Google not valid, try again')
                )


class AccountSerializer(serializers.Serializer):
    username = serializers.SerializerMethodField()
    firstname = serializers.SerializerMethodField()
    lastname = serializers.SerializerMethodField()
    middlename = serializers.SerializerMethodField()
    birthday = serializers.SerializerMethodField()
    nationality = serializers.SerializerMethodField()
    residency = serializers.SerializerMethodField()
    is_email_confirmed = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    success = serializers.SerializerMethodField()

    class Meta:
        fields = ('success', 'username', 'firstname', 'lastname', 'middlename',
                  'birthday', 'nationality', 'residency', 'is_email_confirmed', 'status')

    def get_firstname(self, obj):
        customer = obj.get_customer() if obj else None
        if isinstance(customer, Personal):
            return obj.personal.firstname
        elif isinstance(customer, Corporate):
            return obj.corporate.contact_firstname
        else:
            return ''

    def get_lastname(self, obj):
        customer = obj.get_customer() if obj else None
        if isinstance(customer, Personal):
            return obj.personal.lastname
        elif isinstance(customer, Corporate):
            return obj.corporate.contact_lastname
        else:
            return ''

    def get_middlename(self, obj):
        customer = obj.get_customer() if obj else None
        if isinstance(customer, Personal):
            return obj.personal.middlename
        elif isinstance(customer, Corporate):
            return obj.corporate.contact_middlename
        else:
            return ''

    def get_birthday(self, obj):
        customer = obj.get_customer() if obj else None
        if isinstance(customer, Personal):
            return obj.personal.birthday
        elif isinstance(customer, Corporate):
            return obj.corporate.contact_birthday
        else:
            return ''

    def get_nationality(self, obj):
        customer = obj.get_customer() if obj else None
        if isinstance(customer, Personal):
            return obj.personal.nationality
        elif isinstance(customer, Corporate):
            return obj.corporate.contact_nationality
        else:
            return ''

    def get_residency(self, obj):
        customer = obj.get_customer() if obj else None
        if isinstance(customer, Personal):
            return obj.personal.country
        elif isinstance(customer, Corporate):
            return obj.corporate.contact_residency
        else:
            return ''

    def get_success(self, obj):
        return True if obj else False

    def get_username(self, obj):
        return obj.user.email

    def get_is_email_confirmed(self, obj):
        return Account.is_user_email_confirmed(obj.user)

    def get_status(self, obj):
        def is_personal_data_filled(obj):
            customer = obj.get_customer() if obj else None
            return True if customer and \
                           (customer.status == str(CustomerStatus.submitted) or
                            customer.status == str(CustomerStatus.declined)) else False

        if not obj:
            return ''

        if obj.is_blocked:
            return str(AccountStatus.blocked)

        if not Account.is_user_email_confirmed(obj.user):
            return str(AccountStatus.email_confirmation)

        if not is_personal_data_filled(obj) and \
            obj.is_identity_declined:
            return str(AccountStatus.declined)

        if is_personal_data_filled(obj) and \
            not obj.is_identity_verified and \
            not obj.is_identity_declined:
            return str(AccountStatus.pending)
        elif is_personal_data_filled(obj) and \
            obj.is_identity_verified and \
            not obj.is_identity_declined:
            return str(AccountStatus.verified)
        elif is_personal_data_filled(obj) and \
            obj.is_identity_declined:
            return str(AccountStatus.declined)

        if obj.is_identity_verified:
            return str(AccountStatus.verified)

        return str(AccountStatus.created)


class RegisterSerializer(serializers.Serializer):
    """
    /auth/registration/
    """
    email = serializers.EmailField(required=True, help_text="user's email address")
    password = serializers.CharField(required=True, write_only=True, help_text="user's password")
    captcha = serializers.CharField(required=True, write_only=True, help_text="captcha token")
    tracking = serializers.JSONField(write_only=True, required=False, default=dict, help_text="json with tracking info")

    def validate_username(self, username):
        username = get_adapter().clean_username(username)
        return username

    def validate_email(self, email):
        email = get_adapter().clean_email(email)

        if email:
            email = email.lower()

        if allauth_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                logger.info('A user is already registered with this email address {}'.format(email))
                raise serializers.ValidationError(
                    _("A user is already registered with this e-mail address."))
        return email

    def validate_password(self, password):
        return get_adapter().clean_password(password)

    def validate(self, data):
        return data

    def validate_captcha(self, captcha_token):
        CaptchaHelper.validate_captcha(captcha_token)

    def custom_signup(self, request, user):
        pass

    def get_cleaned_data(self):
        return {
            'username': self.validated_data.get('email', ''),
            'password1': self.validated_data.get('password', ''),
            'email': self.validated_data.get('email', '')
        }

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        adapter.save_user(request, user, self)
        self.custom_signup(request, user)
        setup_user_email(request, user, [])
        tracking = self.validated_data.get('tracking', {})
        account = Account.objects.create(user=user, tracking=tracking)
        ga_integration.on_status_new(account)

        logger.info('User {} successfully registered'.format(self.cleaned_data['email']))

        return user


# Get the UserModel
UserModel = get_user_model()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, allow_blank=False, help_text="user's email")
    password = serializers.CharField(style={'input_type': 'password'}, help_text="user's password")
    captcha = serializers.CharField(required=True, write_only=True, help_text="captcha token")

    def validate_captcha(self, captcha_token):
        CaptchaHelper.validate_captcha(captcha_token)

    def _validate_email(self, email, password):
        user = None

        if email and password:
            user = authenticate(email=email, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username(self, username, password):
        user = None

        if username and password:
            user = authenticate(username=username, password=password)
        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username_email(self, username, email, password):
        user = None

        if email and password:
            user = authenticate(email=email, password=password)
        elif username and password:
            user = authenticate(username=username, password=password)
        else:
            msg = _('Must include either "username" or "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def validate(self, attrs):
        username = attrs.get('email')
        email = attrs.get('email')
        password = attrs.get('password')

        user = None

        if username:
            username = username.lower()

        if email:
            email = email.lower()

        if 'allauth' in settings.INSTALLED_APPS:
            from allauth.account import app_settings

            # Authentication through email
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
                user = self._validate_email(email, password)

            # Authentication through username
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
                user = self._validate_username(username, password)

            # Authentication through either username or email
            else:
                user = self._validate_username_email(username, email, password)

        else:
            # Authentication without using allauth
            if email:
                try:
                    username = UserModel.objects.get(email__iexact=email).get_username()
                except UserModel.DoesNotExist:
                    pass

        if username:
            user = self._validate_username_email(username, '', password)

        # Did we get back an active user?
        if user:
            if hasattr(user, 'account') and user.account.is_blocked:
                msg = _('Your account is blocked.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(_('E-mail is not verified.'))

        attrs['user'] = user
        return attrs


class CustomPasswordResetForm(PasswordResetForm):

    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):
        """
        Send a django.core.mail.EmailMultiAlternatives to `to_email`.
        """
        activate_url = FRONTEND_URL+'/auth/recovery/confirm/{uid}/{token}'.format(**context)
        logger.info("{} {}".format(to_email, activate_url))
        notify.send_email_password_reset(to_email, activate_url, None)


class CustomPasswordResetSerializer(PasswordResetSerializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    email = serializers.EmailField()
    captcha = serializers.CharField(required=True, write_only=True)

    password_reset_form_class = CustomPasswordResetForm

    def get_email_options(self):
        """Override this method to change default e-mail options"""
        return {}

    def validate_email(self, email):
        email = get_adapter().clean_email(email)
        if email:
            email = email.lower()

        try:
            user = UserModel._default_manager.get(email=email)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            logger.info('PasswordReset: Invalid email {}'.format(email))
            raise exceptions.ValidationError(_('Invalid email.'))

        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return email

    def validate_captcha(self, captcha_token):
        CaptchaHelper.validate_captcha(captcha_token)

    def save(self):
        logger.info('PasswordReset: email sent successfully {}'.format(self.validated_data['email']))
        request = self.context.get('request')
        # Set some values to trigger the send_email method.
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'request': request,
        }

        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    new_password = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput,
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_new_password(self):
        password1 = self.cleaned_data.get('new_password')
        password_validation.validate_password(password1, self.user)
        return password1

    def save(self, commit=True):
        password = self.cleaned_data["new_password"]
        self.user.set_password(password)
        if commit:
            self.user.save()
        return self.user


class CustomPasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change.
    """
    old_password = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = getattr(
            settings, 'OLD_PASSWORD_FIELD_ENABLED', False
        )
        self.logout_on_password_change = getattr(
            settings, 'LOGOUT_ON_PASSWORD_CHANGE', False
        )
        super(CustomPasswordChangeSerializer, self).__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop('old_password')

        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            logger.info('PasswordChange: invalid old_password user:{}'.format(self.user.username if self.user else '-'))
            raise serializers.ValidationError('Invalid password')
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        logger.info('PasswordChange: password changed user: {}'.format(self.user.username if self.user else '-'))
        self.set_password_form.save()
        if not self.logout_on_password_change:
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(self.request, self.user)


class CustomPasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    new_password = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        self._errors = {}

        # Decode the uidb64 to uid to get User object
        try:
            uid = force_text(uid_decoder(attrs['uid']))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            logger.info('PasswordResetConfirm: invalid uid ({})'.format(attrs['uid']))
            raise exceptions.ValidationError({'uid': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs['token']):
            logger.info('PasswordResetConfirm: invalid token ({}) user: {}'.format(attrs['token'], self.user.username))
            raise exceptions.ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
        logger.info('PasswordResetConfirm: successfully confirmed user: {}'.format(self.user.username))
        notify.send_email_password_reset_confirmation(self.user.email if self.user else None,
                                                      self.user.pk if self.user else None)
        return self.set_password_form.save()


class ResendEmailConfirmationSerializer(serializers.Serializer):
    pass


class OperationConfirmSerializer(serializers.Serializer):
    operation_id = serializers.CharField()
    token = serializers.CharField()


class AccountUpdateSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    birthday = serializers.DateField(required=False)

    class Meta:
        model = Document
        fields = ('passport', 'utilitybills', 'first_name'
                  'last_name', 'birthday', 'citizenship', 'residency')

    def get_document_url(self, request, path):
        return "{}://{}{}".format("https" if request.is_secure() else "http",
                                  request.get_host(),
                                  path)

    def save(self, account):
        current_site = Site.objects.get_current()
        serializer_fields = self.get_fields()

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('first_name') and self.validated_data.get('first_name'):
                is_updated = True
                account.first_name = self.validated_data['first_name']
            if serializer_fields.get('last_name') and self.validated_data.get('last_name'):
                is_updated = True
                account.last_name = self.validated_data['last_name']
            if serializer_fields.get('birthday') and self.validated_data.get('birthday'):
                is_updated = True
                account.birthday = self.validated_data['birthday']
            if is_updated:
                account.last_updated_at = timezone.now()
            account.save()


class AccountInitSerializer(serializers.Serializer):
    passport = serializers.FileField(required=True)
    utilitybills = serializers.FileField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    birthday = serializers.DateField(required=True)
    citizenship = serializers.CharField(required=True)
    residency = serializers.CharField(required=True)

    class Meta:
        model = Document
        fields = ('passport', 'utilitybills', 'first_name'
                  'last_name', 'birthday', 'citizenship', 'residency')

    def save(self, account):
        current_site = Site.objects.get_current()
        serializer_fields = self.get_fields()

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('passport') and self.validated_data.get('passport'):
                is_updated = True
                passport_document = Document.objects.create(user=account.user)
                passport_document.image = self.validated_data['passport']
                passport_document.type = 'passport'
                passport_document.ext = DocumentHelper.get_document_filename_extension(passport_document.image.name)
                passport_document.save()
            if serializer_fields.get('utilitybills') and self.validated_data.get('utilitybills'):
                is_updated = True
                utilitybills_document = Document.objects.create(user=account.user)
                utilitybills_document.image = self.validated_data['utilitybills']
                utilitybills_document.type = 'utilitybills'
                utilitybills_document.ext = DocumentHelper.get_document_filename_extension(utilitybills_document.image.name)
                utilitybills_document.save()
            if serializer_fields.get('first_name') and self.validated_data.get('first_name'):
                is_updated = True
                account.first_name = self.validated_data['first_name']
            if serializer_fields.get('last_name') and self.validated_data.get('last_name'):
                is_updated = True
                account.last_name = self.validated_data['last_name']
            if serializer_fields.get('citizenship') and self.validated_data.get('citizenship'):
                is_updated = True
                account.citizenship = self.validated_data['citizenship']
            if serializer_fields.get('birthday') and self.validated_data.get('birthday'):
                is_updated = True
                account.birthday = self.validated_data['birthday']
            if serializer_fields.get('residency') and self.validated_data.get('residency'):
                is_updated = True
                account.residency = self.validated_data['residency']
            if is_updated:
                account.last_updated_at = timezone.now()
            account.save()


class AddressesSerializer(serializers.ModelSerializer):
    """
    {
        address: '0x123456789',
        type: 'eth',
        is_verified: True,
    }
    """
    class Meta:
        model = Address
        fields = ('address', 'type', 'is_verified')


class ApplicationsSerializer(serializers.ModelSerializer):
    """
    [{
        "app_uuid": "12ad8648-c15d-47f9-9b36-47675a3af79e",
        "created_at": "2018-04-24 12:35:59",
        "source_address": "0xf93ab5a00fab5b18c25d35a2329813203104f1e8",
        "rec_address": "0x60cb8ecadf2a81914b46086066718737ff89af51",
        "incoming_tx_id": "0xf93ab5a00",
        "incoming_tx_value": 1,
        "outgoing_tx_id": "0x60cb8ecad",
        "outgoing_tx_value": 1810.0,
        "base_currency": "eth",
        "reciprocal_currency": "jAED",
        "base_amount": 1.0,
        "reciprocal_amount": 1810.0,
        "reciprocal_amount_actual": 1810.0,
        "rate": 1810.0,
        "is_active": true
        "status": "created",
        "reason": "",
        "round_digits": 2,
        "fee": 50.0
    }]
    """
    app_uuid = serializers.SerializerMethodField()
    incoming_tx_id = serializers.SerializerMethodField()
    incoming_tx_value = serializers.SerializerMethodField()
    outgoing_tx_id = serializers.SerializerMethodField()
    outgoing_tx_value = serializers.SerializerMethodField()
    source_address = serializers.SerializerMethodField()
    base_amount = serializers.SerializerMethodField()
    reciprocal_amount = serializers.SerializerMethodField()
    reciprocal_amount_actual = serializers.SerializerMethodField()
    rate = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    round_digits = serializers.SerializerMethodField()
    fee = serializers.SerializerMethodField(help_text='Exchange fee (JNT)')

    class Meta:
        model = Application
        fields = ('app_uuid', 'created_at', 'expired_at', 'incoming_tx_id', 'outgoing_tx_id',
                  'incoming_tx_value', 'outgoing_tx_value', 'source_address', 'exchanger_address',
                  'base_currency', 'base_amount', 'reciprocal_currency', 'reciprocal_amount_actual',
                  'reciprocal_amount', 'rate', 'is_active', 'status', 'is_reverse', 'reason', 'round_digits',
                  'fee')

    def get_fee(self, obj):
        return obj.fee

    def get_round_digits(self, obj):
        rec_currency = obj.currency_pair.base_currency if obj.is_reverse else \
            obj.currency_pair.reciprocal_currency

        return rec_currency.round_digits

    def get_status(self, obj):
        if obj.status == str(ApplicationStatus.refunded):
            return str(ApplicationStatus.cancelled)
        else:
            return obj.status

    def get_rate(self, obj):
        rate = obj.rate
        if obj.is_reverse:
            rate = math.calc_reverse_rate(obj.rate)
        return rate

    def is_application_confirmed(self, obj):
        return obj.status != str(ApplicationStatus.created) and \
               obj.status != str(ApplicationStatus.waiting) and \
               obj.status != str(ApplicationStatus.confirming)

    def get_base_amount(self, obj):
        base_amount = obj.base_amount
        if obj.incoming_txs.count() > 0 and \
                self.is_application_confirmed(obj):
            base_amount = obj.incoming_txs.first().value
        return base_amount

    def get_reciprocal_amount(self, obj):
        reciprocal_amount = obj.reciprocal_amount

        if obj.incoming_txs.count() > 0 and \
                self.is_application_confirmed(obj):
            reciprocal_amount = math.round_amount(math.calc_reciprocal_amount(obj.incoming_txs.first().value, obj.rate),
                                                  obj.currency_pair,
                                                  obj.is_reverse,
                                                  False)
        return reciprocal_amount

    def get_reciprocal_amount_actual(self, obj):
        reciprocal_amount = obj.reciprocal_amount

        if obj.incoming_txs.count() > 0:
            reciprocal_amount = math.round_amount(math.calc_reciprocal_amount(obj.incoming_txs.first().value, obj.rate),
                                                  obj.currency_pair,
                                                  obj.is_reverse,
                                                  False)
        return reciprocal_amount

    def get_app_uuid(self, obj):
        return obj.id

    def get_source_address(self, obj):
        return obj.address.address

    def get_incoming_tx(self, obj):
        try:
            txs = IncomingTransaction.objects.filter(application=obj)
            return txs[0] if len(txs) > 0 else None
        except:
            return None

    def get_incoming_tx_id(self, obj):
        tx = self.get_incoming_tx(obj)
        if tx:
            return tx.transaction_id

        return ""

    def get_incoming_tx_value(self, obj):
        tx = self.get_incoming_tx(obj)
        if tx:
            return tx.value

        return 0

    def get_outgoing_tx(self, obj):
        if obj.status == str(ApplicationStatus.converted):
            try:
                txs = Exchange.objects.filter(application=obj)
                return txs[0] if len(txs) > 0 else None
            except:
                return None
        elif obj.status == str(ApplicationStatus.refunded):
            try:
                txs = Refund.objects.filter(application=obj)
                return txs[0] if len(txs) > 0 else None
            except:
                return None
        else:
            return None

    def get_outgoing_tx_id(self, obj):
        tx = self.get_outgoing_tx(obj)
        if tx:
            return tx.transaction_id

        return ""

    def get_outgoing_tx_value(self, obj):
        tx = self.get_outgoing_tx(obj)
        if tx:
            return tx.value

        return 0


class AddressVerifySerializer(serializers.Serializer):
    address = serializers.CharField(required=True, allow_blank=False, help_text='address string')
    sig = serializers.CharField(required=True, allow_blank=False, help_text='sig hash from MEW')
    message_uuid = serializers.CharField(required=True, allow_blank=False, help_text='uuid from address creation response')

    def validate(self, attrs):
        address = attrs.get('address')
        sig = attrs.get('sig')
        message_uuid = attrs.get('message_uuid')

        address_verify = AddressVerify.objects.filter(id=message_uuid).latest('created_at')
        if address_verify is None:
            raise exceptions.ValidationError(_('Address does not exists.'))

        if not address == address_verify.address.address:
            raise exceptions.ValidationError(_('Address does not exists.'))

        if not eth_sign.verifySign(address_verify.message, sig, address_verify.address.address):
            raise exceptions.ValidationError(_('Address verification failed.'))

        return attrs

    def save(self):
        address_verify = AddressVerify.objects.filter(id=self.validated_data['message_uuid']).first()
        address = Address.objects.filter(id=address_verify.address_id).first()
        with transaction.atomic():
            address_verify.is_verified = True
            address_verify.save()
            address.is_verified = True
            address.save()

    class Meta:
        model = AddressVerify
        fields = ('address', 'sig', 'message_uuid')


class CurrencyRateSerializer(serializers.Serializer):
    base_currency = serializers.CharField(required=True, allow_blank=False)
    rec_currency = serializers.CharField(required=True, allow_blank=False)
    amount = serializers.FloatField(required=True)
    type = serializers.CharField(required=True, help_text='base | rec')

    def validate(self, attrs):
        amount_attr = attrs.get('amount')

        if attrs['type'] == ApplicationAmountType.base:
            attrs['base_amount'] = amount_attr
        elif attrs['type'] == ApplicationAmountType.rec:
            attrs['rec_amount'] = amount_attr
        else:
            raise serializers.ValidationError(_('Wrong amount type.'))

        return attrs


class OpenCurrencyRateSerializer(serializers.Serializer):
    pass


class CurrencySerializer(serializers.Serializer):
    pass


class RemoveAddressSerializer(serializers.Serializer):
    address = serializers.CharField(required=True, allow_blank=False)

    class Meta:
        model = Address
        fields = ('address')

    def save(self):
        address = self.validated_data['address_obj']
        with transaction.atomic():
            address.is_removed = True
            address.save()
            notify.send_email_eth_address_removed(address.user.email if address.user else None,
                                                  address.address,
                                                  address.user.id if address.user else None)

    def validate(self, attrs):
        user = self.context.get('user')
        if not user:
            raise serializers.ValidationError(_('Unknown user.'))
        try:
            address = Address.objects.get(address__iexact=attrs.get('address'), user=user)
        except Address.DoesNotExist:
            raise serializers.ValidationError(_('address does not exist.'))

        if address.is_removed:
            raise serializers.ValidationError(_('address already removed.'))

        attrs['address_obj'] = address

        return attrs


class AddressSerializer(serializers.Serializer):
    address = serializers.CharField(required=True, allow_blank=False)
    type = serializers.CharField(required=True, allow_blank=False, help_text='types: ["eth",]')

    class Meta:
        model = Address
        fields = ('address', 'type', 'message', 'uuid')

    def generate_message(self, address):
        return LOGIC__ADDRESS_VERIFY_TEXT.format(address.user.account.first_name,
                                                 address.user.account.last_name,
                                                 address.address,
                                                 timezone.now().strftime('%Y %B %d %I:%M %p'))

    def save(self, user):
        address = None
        try:
            address = Address.objects.get(address__iexact=self.validated_data['address'], user=user)
        except Address.DoesNotExist:
            pass
        with transaction.atomic():
            if not address:
                address = Address.objects.create(user=user, **self.validated_data)
            else:
                if address.is_removed or address.is_rejected or not address.is_verified:
                    address.is_removed = False
                    address.is_rejected = False
                    address.is_verified = False
            address.is_verified = True
            address.save()
            address_verify = AddressVerify.objects.create(address=address,
                                                          message=self.generate_message(address))
            address_verify.save()
            notify.send_email_eth_address_added(user.email if user else None,
                                                address.address,
                                                user.id if user else None)

        self.validated_data['message'] = address_verify.message
        self.validated_data['uuid'] = address_verify.id
        self.validated_data['success'] = True

    def validate(self, attrs):
        user = self.context.get('user')
        address = attrs.get('address')
        type = attrs.get('type')

        if type and type=='eth' and address:
            if not eth_address.is_valid_address(address):
                raise serializers.ValidationError(_('Ethereum address is not valid.'))
        elif not address:
            raise serializers.ValidationError(_('Must include "address".'))
        elif not type:
            raise serializers.ValidationError(_('Must include "type".'))
        elif type != 'eth':
            raise serializers.ValidationError(_('The type of address must be "eth".'))

        try:
            address_obj = Address.objects.get(address__iexact=address)
            if address_obj.user_id != user.pk:
                raise serializers.ValidationError(_('This address already used.'))
            elif not address_obj.is_removed and not address_obj.is_rejected and address_obj.is_verified:
                raise serializers.ValidationError(_('This address already exists.'))
        except Address.DoesNotExist:
            pass

        attrs['address'] = address
        attrs['type'] = type
        attrs['is_verified'] = False
        return attrs


class ApplicationAmountType:
    base = 'base'
    rec = 'rec'


class ApplicationSerializer(serializers.Serializer):
    address = serializers.CharField(required=False)
    base_currency = serializers.CharField(required=True)
    rec_currency = serializers.CharField(required=True)
    amount = serializers.FloatField(required=True)
    type = serializers.CharField(required=True, help_text='base | rec')
    uuid = serializers.CharField(required=True)

    def validate(self, attrs):
        user = self.context.get('user')
        if not user:
            raise serializers.ValidationError(_('Unknown user.'))

        if user.account.is_blocked:
            raise exceptions.ValidationError(_('Account is blocked.'))

        active_application = user.applications.filter(is_active=True).first()
        if active_application:
            raise exceptions.ValidationError(_('There can only be one active application.'))

        address_attr = attrs.get('address')
        base_currency_attr = attrs.get('base_currency')
        rec_currency_attr = attrs.get('rec_currency')
        amount_attr = attrs.get('amount')
        rate_uuid = attrs.get('uuid')

        user_addresses = Address.objects.filter(user=user, is_verified=True, is_removed=False)
        if user_addresses.count() == 0:
            raise serializers.ValidationError(_('You have no addresses.'))

        if address_attr is None and user_addresses.count() > 1:
            raise serializers.ValidationError(_('"address" not specified.'))

        if address_attr is not None:
            app_address = user_addresses.filter(address=address_attr).first()
            if app_address is None:
                raise serializers.ValidationError(_('specified "address" does not exist.'))

        cur_address = user_addresses[0] if user_addresses.count() == 1 else app_address

        attrs['address_id'] = cur_address.pk

        is_reverse_operation = False
        currency_pair = CurrencyPair.objects.filter(base_currency__display_name=base_currency_attr,
                                                    reciprocal_currency__display_name=rec_currency_attr,
                                                    is_exchangeable=True).first()
        if not currency_pair:
            is_reverse_operation = True
            currency_pair = CurrencyPair.objects.filter(base_currency__display_name=rec_currency_attr,
                                                        reciprocal_currency__display_name=base_currency_attr,
                                                        is_exchangeable=True).first()
        if not currency_pair:
            raise serializers.ValidationError(_('specified "currency" not found.'))

        attrs['exchanger_address'] = currency_pair.base_currency.exchanger_address if not is_reverse_operation else \
            currency_pair.reciprocal_currency.exchanger_address

        attrs['currency_pair_id'] = currency_pair.pk

        currency_pair_rate = currency_pair.currency_pair_rates.filter(id=rate_uuid).first()

        if not currency_pair_rate:
            raise serializers.ValidationError(_('Currency price does not exists.'))

        if currency_pair_rate.currency_pair.pk != currency_pair.pk:
            raise serializers.ValidationError(_('Wrong currency price.'))

        if abs((datetime.now(tzlocal()) - currency_pair_rate.created_at).seconds) > LOGIC__OUT_OF_DATE_PRICE_SEC:
            logger.error('Сurrency price {} is out of date'.format(currency_pair.display_name))
            raise serializers.ValidationError(_('Сurrency price is out of date.'))

        currency_pair_rate_price = currencyrates.get_currency_pair_rate(currency_pair_rate, is_reverse_operation)

        if is_reverse_operation:
            currency_pair_rate_price = math.calc_reverse_rate(currency_pair_rate_price)

        attrs['currency_pair_rate_id'] = currency_pair_rate.pk
        attrs['rate'] = currency_pair_rate_price

        if attrs['type'] == ApplicationAmountType.base:
            attrs['base_amount'] = math.round_amount(amount_attr,
                                                     currency_pair,
                                                     is_reverse_operation,
                                                     True)
            attrs['reciprocal_amount'] = math.round_amount(math.calc_reciprocal_amount(attrs['base_amount'],
                                                                                       currency_pair_rate_price),
                                                           currency_pair,
                                                           is_reverse_operation,
                                                           False)
        elif attrs['type'] == ApplicationAmountType.rec:
            attrs['reciprocal_amount'] = math.round_amount(amount_attr,
                                                           currency_pair,
                                                           is_reverse_operation,
                                                           False)
            attrs['base_amount'] = math.round_amount(math.calc_base_amount(attrs['reciprocal_amount'],
                                                                           currency_pair_rate_price),
                                                     currency_pair,
                                                     is_reverse_operation,
                                                     True)
        else:
            raise serializers.ValidationError(_('Wrong amount type.'))

        if attrs['base_amount'] == 0.0:
            raise serializers.ValidationError(_('A valid number is required.'))

        if not math.check_amount_min_limit(attrs['base_amount'], currency_pair, is_reverse_operation, True):
            raise serializers.ValidationError(_('Exchange value is under-limit'))

        if not math.check_amount_max_limit(attrs['base_amount'], currency_pair, is_reverse_operation, True):
            raise serializers.ValidationError(_('Exchange value is over-limit'))

        if utils.get_currency_balance(
                currency_pair.base_currency if is_reverse_operation else \
                        currency_pair.reciprocal_currency) < attrs['reciprocal_amount']:
            raise serializers.ValidationError(_('Exchange value is too large'))

        try:
            feeJNT = eth_contracts.feeJNT(currency_pair.reciprocal_currency.abi,
                                          currency_pair.reciprocal_currency.exchanger_address,
                                          currency_pair.reciprocal_currency.is_erc20_token)
        except:
            raise serializers.ValidationError(_('Server error'))
        else:
            if eth_contracts.balanceJnt(currency_pair.base_currency.abi, address_attr) < feeJNT:
                raise serializers.ValidationError({'jnt': str(ApplicationCancelReason.not_enough_jnt)})

        fee_entry = ExchangeFee.objects.all().order_by("-from_block").first()
        attrs['fee'] = fee_entry.value if fee_entry else 0.0
        attrs['is_reverse_operation'] = is_reverse_operation

        return attrs

    def save(self):
        user = self.context['user']
        with transaction.atomic():
            application = Application.objects.create(user=user,
                                                     is_active=True,
                                                     is_reverse=self.validated_data['is_reverse_operation'],
                                                     address_id=self.validated_data['address_id'],
                                                     currency_pair_id=self.validated_data['currency_pair_id'],
                                                     currency_pair_rate_id=self.validated_data['currency_pair_rate_id'],
                                                     base_currency=self.validated_data['base_currency'],
                                                     reciprocal_currency=self.validated_data['rec_currency'],
                                                     rate=self.validated_data['rate'],
                                                     base_amount=self.validated_data['base_amount'],
                                                     base_amount_actual=self.validated_data['base_amount'],
                                                     reciprocal_amount=self.validated_data['reciprocal_amount'],
                                                     reciprocal_amount_actual=self.validated_data['reciprocal_amount'],
                                                     exchanger_address=self.validated_data['exchanger_address'],
                                                     expired_at=timezone.now() + timedelta(seconds=LOGIC__EXPIRATION_LIMIT_SEC),
                                                     fee=self.validated_data['fee'])
            application.save()
            self.validated_data['application_id'] = application.pk
            notify.send_email_exchange_request(
                user.email,
                notify._format_float_value(self.validated_data['base_amount'],
                                          self.validated_data['base_currency']),
                notify._format_float_value(self.validated_data['reciprocal_amount'],
                                          self.validated_data['rec_currency']),
                self.validated_data['address'],
                notify._format_conversion_rate(
                    math._roundDown(self.validated_data['rate'], 2) if not self.validated_data['is_reverse_operation'] else \
                        math._roundUp(1.0 / self.validated_data['rate'], 2),
                    'ETH',
                    self.validated_data['base_currency'] if self.validated_data['is_reverse_operation'] else \
                        self.validated_data['rec_currency']),
                user_id=user.pk)


class ApplicationRefundSerializer(serializers.Serializer):
    app_uuid = serializers.UUIDField(required=True)

    def validate(self, data):
        try:
            self.application = Application.objects.get(id=data['app_uuid'])
        except Application.DoesNotExist:
            raise serializers.ValidationError(_('Application does not exists.'))

        if not self.application.is_active or \
                not self.application.status == str(ApplicationStatus.confirming):
            raise serializers.ValidationError(_('This operation is not possible now.'))

        return data

    def save(self):
        with transaction.atomic():
            if self.application:
                self.application.status = str(ApplicationStatus.refunding)
                self.application.reason = str(ApplicationCancelReason.cancelled_by_user)
                self.application.save()


class ApplicationConfirmSerializer(serializers.Serializer):
    app_uuid = serializers.UUIDField(required=True)

    def validate(self, data):
        try:
            self.application = Application.objects.get(id=data['app_uuid'])
        except Application.DoesNotExist:
            raise serializers.ValidationError(_('Application does not exists.'))

        if not self.application.is_active or \
                not self.application.status == str(ApplicationStatus.confirming):
            raise serializers.ValidationError(_('This operation is not possible now.'))

        if self.application.expired_at < datetime.now(tzlocal()):
            raise serializers.ValidationError(_('Application expired.'))

        return data

    def save(self):
        with transaction.atomic():
            if self.application:
                self.application.status = str(ApplicationStatus.converting)
                self.application.save()


class ApplicationFinishSerializer(serializers.Serializer):
    app_uuid = serializers.UUIDField(required=True)

    def validate(self, data):
        try:
            self.application = Application.objects.get(id=data['app_uuid'])
        except Application.DoesNotExist:
            raise serializers.ValidationError(_('Application does not exists.'))

        if not self.application.is_active or \
                not (self.application.status == str(ApplicationStatus.refunded) or \
                     self.application.status == str(ApplicationStatus.converted) or \
                     self.application.status == str(ApplicationStatus.cancelled)):
            raise serializers.ValidationError(_('This operation is not possible now.'))

        return data

    def save(self):
        with transaction.atomic():
            if self.application:
                self.application.is_active = False
                self.application.save()


class ApplicationCancelSerializer(serializers.Serializer):
    app_uuid = serializers.UUIDField(required=True)

    def validate(self, data):
        try:
            self.application = Application.objects.get(id=data['app_uuid'])
        except Application.DoesNotExist:
            raise serializers.ValidationError(_('Application does not exists.'))

        if not self.application.is_active or \
                not self.application.status == str(ApplicationStatus.created):
            raise serializers.ValidationError(_('This operation is not possible now.'))

        return data

    def save(self):
        with transaction.atomic():
            if self.application:
                self.application.status = str(ApplicationStatus.cancelled)
                self.application.reason = str(ApplicationCancelReason.cancelled_by_user)
                self.application.is_active = False
                self.application.save()
                notify.send_email_exchange_unsuccessful(
                    self.application.user.email,
                    notify._format_float_value(self.application.base_amount_actual,
                                              self.application.base_currency),
                    ApplicationCancelReason.__dict__[self.application.reason].description \
                        if self.application.reason in ApplicationCancelReason.__dict__ \
                        else "An unexpected error occured",
                    user_id=self.application.user.pk)


class PersonalContactInfoSerializer(serializers.Serializer):
    """
    Serializer for update personal contact information.
    """
    firstname = serializers.CharField(required=True, max_length=PersonalFieldLength.fullname,
                                      min_length=1)
    lastname = serializers.CharField(required=True, max_length=PersonalFieldLength.fullname,
                                     min_length=1)
    middlename = serializers.CharField(required=False, max_length=PersonalFieldLength.fullname,
                                       min_length=1, allow_blank=True)
    nationality = serializers.CharField(required=True, max_length=PersonalFieldLength.nationality,
                                        min_length=1)
    birthday = CustomDateField(
        required=True,
        validators=[
            BirthdayValidator(18),
        ])
    phone = serializers.CharField(required=True, max_length=PersonalFieldLength.phone,
                                  min_length=1)

    class Meta:
        model = Personal
        fields = ('firstname', 'lastname', 'middlename', 'nationality', 'birthday', 'phone')

    def save(self, personal):
        serializer_fields = self.get_fields()

        logger.info('PersonalContractInfo: succeeded {}'.format(personal.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('firstname') and self.validated_data.get('firstname'):
                is_updated = True
                personal.firstname = self.validated_data['firstname']
            if serializer_fields.get('lastname') and self.validated_data.get('lastname'):
                is_updated = True
                personal.lastname = self.validated_data['lastname']
            if serializer_fields.get('middlename') and self.validated_data.get('middlename'):
                is_updated = True
                personal.middlename = self.validated_data['middlename']
            if serializer_fields.get('nationality') and self.validated_data.get('nationality'):
                is_updated = True
                personal.nationality = self.validated_data['nationality']
            if serializer_fields.get('birthday') and self.validated_data.get('birthday'):
                is_updated = True
                personal.birthday = self.validated_data['birthday']
            if serializer_fields.get('phone') and self.validated_data.get('phone'):
                is_updated = True
                personal.phone = self.validated_data['phone']
            if is_updated:
                personal.last_updated_at = timezone.now()
                if personal.account is not None:
                    personal.account.last_updated_at = timezone.now()
                    personal.account.type = AccountType.personal
                    personal.account.save()
                personal.status = str(CustomerStatus.address)
                personal.save()


class PersonalAddressSerializer(serializers.Serializer):
    """
    Serializer for update residential / address.
    """
    country = serializers.CharField(required=True, max_length=PersonalFieldLength.country,
                                    min_length=1)
    street = serializers.CharField(required=True, max_length=PersonalFieldLength.street,
                                   min_length=1)
    apartment = serializers.CharField(required=False, allow_blank=True, max_length=PersonalFieldLength.apartment,
                                      min_length=1)
    city = serializers.CharField(required=True, max_length=PersonalFieldLength.city,
                                 min_length=1)
    postcode = serializers.CharField(required=True, max_length=PersonalFieldLength.postcode,
                                     min_length=1)

    class Meta:
        model = Personal
        fields = ('country', 'street', 'apartment', 'city', 'postcode')

    def save(self, personal):
        serializer_fields = self.get_fields()

        logger.info('PersonalAddress: succeeded {}'.format(personal.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('country') and self.validated_data.get('country'):
                is_updated = True
                personal.country = self.validated_data['country']
            if serializer_fields.get('street') and self.validated_data.get('street'):
                is_updated = True
                personal.street = self.validated_data['street']
            if serializer_fields.get('apartment') and self.validated_data.get('apartment'):
                is_updated = True
                personal.apartment = self.validated_data['apartment']
            if serializer_fields.get('city') and self.validated_data.get('city'):
                is_updated = True
                personal.city = self.validated_data['city']
            if serializer_fields.get('postcode') and self.validated_data.get('postcode'):
                is_updated = True
                personal.postcode = self.validated_data['postcode']
            if is_updated:
                personal.last_updated_at = timezone.now()
                if personal.account is not None:
                    personal.account.last_updated_at = timezone.now()
                    personal.account.type = AccountType.personal
                    personal.account.save()
                personal.status = str(CustomerStatus.income_info)
                personal.save()


class PersonalIncomeInfoSerializer(serializers.Serializer):
    """
    Serializer for update income information.
    """
    profession = serializers.CharField(required=True, max_length=PersonalFieldLength.profession,
                                       min_length=1)
    income_source = serializers.CharField(required=True, max_length=PersonalFieldLength.income_source,
                                          min_length=1)
    assets_origin = serializers.CharField(required=True, max_length=PersonalFieldLength.assets_origin,
                                           min_length=1)
    jcash_use = serializers.CharField(required=True, max_length=PersonalFieldLength.jcash_use,
                                      min_length=1)

    class Meta:
        model = Personal
        fields = ('profession', 'income_source', 'assets_origin', 'jcash_use')

    def save(self, personal):
        serializer_fields = self.get_fields()

        logger.info('PersonalIncomeInfo: succeeded {}'.format(personal.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('profession') and self.validated_data.get('profession'):
                is_updated = True
                personal.profession = self.validated_data['profession']
            if serializer_fields.get('income_source') and self.validated_data.get('income_source'):
                is_updated = True
                personal.income_source = self.validated_data['income_source']
            if serializer_fields.get('assets_origin') and self.validated_data.get('assets_origin'):
                is_updated = True
                personal.assets_origin = self.validated_data['assets_origin']
            if serializer_fields.get('jcash_use') and self.validated_data.get('jcash_use'):
                is_updated = True
                personal.jcash_use = self.validated_data['jcash_use']
            if is_updated:
                personal.last_updated_at = timezone.now()
                if personal.account is not None:
                    personal.account.last_updated_at = timezone.now()
                    personal.account.type = AccountType.personal
                    personal.account.save()
                personal.status = str(CustomerStatus.documents)
                personal.save()


class PersonalDocumentsSerializer(serializers.Serializer):
    """
    Serializer for upload documents.
    """
    passport = serializers.FileField(required=True)
    utilitybills = serializers.FileField(required=True)
    selfie = serializers.FileField(required=True)

    class Meta:
        model = Personal
        fields = ('passport', 'utilitybills', 'selfie')

    def save(self, personal):
        serializer_fields = self.get_fields()

        logger.info('PersonalDocuments: succeeded {}'.format(personal.account.user.username))

        with transaction.atomic():
            if serializer_fields.get('passport') and self.validated_data.get('passport'):
                passport_document = Document.objects.create(user=personal.account.user, personal=personal)
                passport_document.image = self.validated_data['passport']
                passport_document.group = DocumentGroup.personal
                passport_document.type = DocumentType.passport
                passport_document.ext = DocumentHelper.get_document_filename_extension(passport_document.image.name)
                passport_document.save()
            if serializer_fields.get('utilitybills') and self.validated_data.get('utilitybills'):
                utilitybills_document = Document.objects.create(user=personal.account.user, personal=personal)
                utilitybills_document.image = self.validated_data['utilitybills']
                utilitybills_document.group = DocumentGroup.personal
                utilitybills_document.type = DocumentType.utilitybills
                utilitybills_document.ext = DocumentHelper.get_document_filename_extension(utilitybills_document.image.name)
                utilitybills_document.save()
            if serializer_fields.get('selfie') and self.validated_data.get('selfie'):
                selfie_document = Document.objects.create(user=personal.account.user, personal=personal)
                selfie_document.image = self.validated_data['selfie']
                selfie_document.group = DocumentGroup.personal
                selfie_document.type = DocumentType.selfie
                selfie_document.ext = DocumentHelper.get_document_filename_extension(selfie_document.image.name)
                selfie_document.save()
            personal.last_updated_at = timezone.now()
            if personal.account is not None:
                if personal.account.is_identity_declined:
                    personal.account.is_identity_declined = False
                if personal.account.corporate is not None:
                    if personal.account.corporate.status == str(CustomerStatus.declined):
                        personal.account.corporate.status = str(CustomerStatus.documents)
                        personal.account.corporate.save()

                personal.account.last_updated_at = personal.last_updated_at
                personal.account.type = AccountType.personal
                personal.account.save()
            personal.status = str(CustomerStatus.submitted)
            personal.save()

            doc_verification = DocumentVerification.objects.create(
                user=personal.account.user,
                personal=personal,
                passport=passport_document,
                utilitybills=utilitybills_document,
                selfie=selfie_document,
                meta={'firstname': str(personal.firstname),
                      'lastname': str(personal.lastname),
                      'middlename': str(personal.middlename),
                      'nationality': str(personal.nationality),
                      'birthday': str(personal.birthday),
                      'phone': str(personal.phone),
                      'country': str(personal.country),
                      'street': str(personal.street),
                      'apartment': str(personal.apartment),
                      'city': str(personal.city),
                      'postcode': str(personal.postcode),
                      'profession': str(personal.profession),
                      'income_source': str(personal.income_source),
                      'assets_origin': str(personal.assets_origin),
                      'jcash_use': str(personal.jcash_use)})

            doc_verification.save()
            ga_integration.on_status_registration_complete(personal.account)
            notify.send_email_jcash_application_underway(personal.account.user.email, personal.account.user.pk)


class PersonalSerializer(serializers.ModelSerializer):
    """
    Serializer that takes an additional `status` argument that
    controls which fields of Personal should be displayed.
    """

    passport = serializers.SerializerMethodField()
    utilitybills = serializers.SerializerMethodField()
    selfie = serializers.SerializerMethodField()
    success = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        # Instantiate the superclass normally
        super(PersonalSerializer, self).__init__(*args, **kwargs)

        status = self.context.get('status', '')
        if status == '':
            fields = ('success', 'firstname', 'lastname', 'middlename', 'nationality', 'birthday', 'phone')
        elif status == str(CustomerStatus.address):
            fields = ('success', 'country', 'street', 'apartment', 'city', 'postcode')
        elif status == str(CustomerStatus.income_info):
            fields = ('success', 'profession', 'income_source', 'assets_origin', 'jcash_use')
        elif status == str(CustomerStatus.documents):
            fields = ('success', 'passport', 'utilitybills', 'selfie')
        else:
            fields = ('success',)

        included = set(fields)
        existing = set(self.fields.keys())

        for other in existing - included:
            self.fields.pop(other)

    class Meta:
        model = Personal
        fields = ('success', 'firstname', 'lastname', 'middlename', 'nationality', 'birthday', 'phone',
                  'country', 'street', 'apartment', 'city', 'postcode', 'profession',
                  'income_source', 'assets_origin', 'jcash_use', 'passport', 'utilitybills',
                  'selfie')

    def get_passport(self, obj):
        return ''

    def get_utilitybills(self, obj):
        return ''

    def get_selfie(self, obj):
        return ''

    def get_success(self, obj):
        return True if obj else False


class CorporateCompanyInfoSerializer(serializers.Serializer):
    """
    Serializer for update company info.
    """
    name = serializers.CharField(required=True, max_length=CorporateFieldLength.name,
                                 min_length=1)
    domicile_country = serializers.CharField(required=True, max_length=CorporateFieldLength.country,
                                             min_length=1)
    phone = serializers.CharField(required=True, max_length=CorporateFieldLength.phone,
                                  min_length=1)

    class Meta:
        model = Corporate
        fields = ('name', 'country', 'phone')

    def save(self, corporate):
        serializer_fields = self.get_fields()

        logger.info('CorporateCompanyInfo: succeeded {}'.format(corporate.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('name') and self.validated_data.get('name'):
                is_updated = True
                corporate.name = self.validated_data['name']
            if serializer_fields.get('domicile_country') and self.validated_data.get('domicile_country'):
                is_updated = True
                corporate.domicile_country = self.validated_data['domicile_country']
            if serializer_fields.get('phone') and self.validated_data.get('phone'):
                is_updated = True
                corporate.business_phone = self.validated_data['phone']
            if is_updated:
                corporate.last_updated_at = timezone.now()
                if corporate.account is not None:
                    corporate.account.last_updated_at = timezone.now()
                    corporate.account.type = AccountType.corporate
                    corporate.account.save()
                corporate.status = str(CustomerStatus.business_address)
                corporate.save()


class CorporateAddressSerializer(serializers.Serializer):
    """
    Serializer for update business address.
    """
    country = serializers.CharField(required=True, max_length=CorporateFieldLength.country,
                                    min_length=1)
    street = serializers.CharField(required=True, max_length=CorporateFieldLength.street,
                                   min_length=1)
    apartment = serializers.CharField(required=False, allow_blank=True, max_length=CorporateFieldLength.apartment,
                                      min_length=1)
    city = serializers.CharField(required=True, max_length=CorporateFieldLength.city,
                                 min_length=1)
    postcode = serializers.CharField(required=True, max_length=CorporateFieldLength.postcode,
                                     min_length=1)

    class Meta:
        model = Corporate
        fields = ('country', 'street', 'apartment', 'city', 'postcode')

    def save(self, corporate):
        serializer_fields = self.get_fields()

        logger.info('CorporateAddress: succeeded {}'.format(corporate.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('country') and self.validated_data.get('country'):
                is_updated = True
                corporate.country = self.validated_data['country']
            if serializer_fields.get('street') and self.validated_data.get('street'):
                is_updated = True
                corporate.street = self.validated_data['street']
            if serializer_fields.get('apartment') and self.validated_data.get('apartment'):
                is_updated = True
                corporate.apartment = self.validated_data['apartment']
            if serializer_fields.get('city') and self.validated_data.get('city'):
                is_updated = True
                corporate.city = self.validated_data['city']
            if serializer_fields.get('postcode') and self.validated_data.get('postcode'):
                is_updated = True
                corporate.postcode = self.validated_data['postcode']
            if is_updated:
                corporate.last_updated_at = timezone.now()
                if corporate.account is not None:
                    corporate.account.last_updated_at = timezone.now()
                    corporate.account.type = AccountType.corporate
                    corporate.account.save()
                corporate.status = str(CustomerStatus.income_info)
                corporate.save()


class CorporateIncomeInfoSerializer(serializers.Serializer):
    """
    Serializer for update income information.
    """
    industry = serializers.CharField(required=True, max_length=CorporateFieldLength.industry,
                                     min_length=1)
    currency_nature = serializers.CharField(required=True, max_length=CorporateFieldLength.currency_nature,
                                            min_length=1)
    assets_origin = serializers.CharField(required=True, max_length=CorporateFieldLength.assets_origin,
                                           min_length=1)
    assets_origin_description = serializers.CharField(required=True,
                                                       max_length=CorporateFieldLength.assets_origin_description,
                                                       min_length=1)
    jcash_use = serializers.CharField(required=True, max_length=CorporateFieldLength.jcash_use,
                                      min_length=1)

    class Meta:
        model = Corporate
        fields = ('industry', 'currency_amount', 'assets_origin', 'assets_origin_description', 'jcash_use')

    def save(self, corporate):
        serializer_fields = self.get_fields()

        logger.info('CorporateIncomeInfo: succeeded {}'.format(corporate.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('industry') and self.validated_data.get('industry'):
                is_updated = True
                corporate.industry = self.validated_data['industry']
            if serializer_fields.get('currency_nature') and self.validated_data.get('currency_nature'):
                is_updated = True
                corporate.currency_nature = self.validated_data['currency_nature']
            if serializer_fields.get('assets_origin') and self.validated_data.get('assets_origin'):
                is_updated = True
                corporate.assets_origin = self.validated_data['assets_origin']
            if serializer_fields.get('assets_origin_description') and self.validated_data.get('assets_origin_description'):
                is_updated = True
                corporate.assets_origin_description = self.validated_data['assets_origin_description']
            if serializer_fields.get('jcash_use') and self.validated_data.get('jcash_use'):
                is_updated = True
                corporate.jcash_use = self.validated_data['jcash_use']
            if is_updated:
                corporate.last_updated_at = timezone.now()
                if corporate.account is not None:
                    corporate.account.last_updated_at = timezone.now()
                    corporate.account.type = AccountType.corporate
                    corporate.account.save()
                corporate.status = str(CustomerStatus.primary_contact)
                corporate.save()


class CorporateContactInfoSerializer(serializers.Serializer):
    """
    Serializer for update primary contact info.
    """
    firstname = serializers.CharField(required=True, max_length=CorporateFieldLength.fullname,
                                      min_length=1)
    lastname = serializers.CharField(required=True, max_length=CorporateFieldLength.fullname,
                                     min_length=1)
    middlename = serializers.CharField(required=False, max_length=CorporateFieldLength.fullname,
                                       min_length=1, allow_blank=True)
    birthday = CustomDateField(
        required=True,
        validators=[
            BirthdayValidator(18),
        ])
    email = serializers.EmailField(required=True, max_length=CorporateFieldLength.email,
                                   min_length=1)
    phone = serializers.CharField(required=True, max_length=CorporateFieldLength.phone,
                                  min_length=1)
    nationality = serializers.CharField(required=True, max_length=CorporateFieldLength.country,
                                        min_length=1)
    residency = serializers.CharField(required=True, max_length=CorporateFieldLength.country,
                                      min_length=1)
    street = serializers.CharField(required=True, max_length=CorporateFieldLength.street,
                                   min_length=1)
    apartment = serializers.CharField(required=False, allow_blank=True, max_length=CorporateFieldLength.apartment,
                                      min_length=1)
    city = serializers.CharField(required=True, max_length=CorporateFieldLength.city,
                                 min_length=1)
    postcode = serializers.CharField(required=True, max_length=CorporateFieldLength.postcode,
                                     min_length=1)

    class Meta:
        model = Corporate
        fields = ('firstname', 'lastname', 'middlename', 'birthday', 'email', 'nationality', 'residency',
                  'street', 'apartment', 'city', 'postcode')

    def save(self, corporate):
        serializer_fields = self.get_fields()

        logger.info('CorporateContactInfo: succeeded {}'.format(corporate.account.user.username))

        with transaction.atomic():
            is_updated = False
            if serializer_fields.get('firstname') and self.validated_data.get('firstname'):
                is_updated = True
                corporate.contact_firstname = self.validated_data['firstname']
            if serializer_fields.get('lastname') and self.validated_data.get('lastname'):
                is_updated = True
                corporate.contact_lastname = self.validated_data['lastname']
            if serializer_fields.get('middlename') and self.validated_data.get('middlename'):
                is_updated = True
                corporate.contact_middlename = self.validated_data['middlename']
            if serializer_fields.get('birthday') and self.validated_data.get('birthday'):
                is_updated = True
                corporate.contact_birthday = self.validated_data['birthday']
            if serializer_fields.get('email') and self.validated_data.get('email'):
                is_updated = True
                corporate.contact_email = self.validated_data['email']
            if serializer_fields.get('phone') and self.validated_data.get('phone'):
                is_updated = True
                corporate.contact_phone = self.validated_data['phone']
            if serializer_fields.get('nationality') and self.validated_data.get('nationality'):
                is_updated = True
                corporate.contact_nationality = self.validated_data['nationality']
            if serializer_fields.get('residency') and self.validated_data.get('residency'):
                is_updated = True
                corporate.contact_residency = self.validated_data['residency']
            if serializer_fields.get('street') and self.validated_data.get('street'):
                is_updated = True
                corporate.contact_street = self.validated_data['street']
            if serializer_fields.get('apartment') and self.validated_data.get('apartment'):
                is_updated = True
                corporate.contact_apartment = self.validated_data['apartment']
            if serializer_fields.get('city') and self.validated_data.get('city'):
                is_updated = True
                corporate.contact_city = self.validated_data['city']
            if serializer_fields.get('postcode') and self.validated_data.get('postcode'):
                is_updated = True
                corporate.contact_postcode = self.validated_data['postcode']
            if is_updated:
                corporate.last_updated_at = timezone.now()
                if corporate.account is not None:
                    corporate.account.last_updated_at = timezone.now()
                    corporate.account.type = AccountType.corporate
                    corporate.account.save()
                corporate.status = str(CustomerStatus.documents)
                corporate.save()


class CorporateDocumentsSerializer(serializers.Serializer):
    """
    Serializer for upload documents.
    """
    passport = serializers.FileField(required=True)
    utilitybills = serializers.FileField(required=True)
    selfie = serializers.FileField(required=True)

    class Meta:
        model = Corporate
        fields = ('passport', 'utilitybills', 'selfie')

    def save(self, corporate):
        serializer_fields = self.get_fields()

        logger.info('CorporateDocuments: succeeded {}'.format(corporate.account.user.username))

        with transaction.atomic():
            if serializer_fields.get('passport') and self.validated_data.get('passport'):
                passport_document = Document.objects.create(user=corporate.account.user, corporate=corporate)
                passport_document.image = self.validated_data['passport']
                passport_document.group = DocumentGroup.corporate
                passport_document.type = DocumentType.passport
                passport_document.ext = DocumentHelper.get_document_filename_extension(passport_document.image.name)
                passport_document.save()
            if serializer_fields.get('utilitybills') and self.validated_data.get('utilitybills'):
                utilitybills_document = Document.objects.create(user=corporate.account.user, corporate=corporate)
                utilitybills_document.image = self.validated_data['utilitybills']
                utilitybills_document.group = DocumentGroup.corporate
                utilitybills_document.type = DocumentType.utilitybills
                utilitybills_document.ext = DocumentHelper.get_document_filename_extension(utilitybills_document.image.name)
                utilitybills_document.save()
            if serializer_fields.get('selfie') and self.validated_data.get('selfie'):
                selfie_document = Document.objects.create(user=corporate.account.user, corporate=corporate)
                selfie_document.image = self.validated_data['selfie']
                selfie_document.group = DocumentGroup.corporate
                selfie_document.type = DocumentType.selfie
                selfie_document.ext = DocumentHelper.get_document_filename_extension(selfie_document.image.name)
                selfie_document.save()
            corporate.last_updated_at = timezone.now()
            if corporate.account is not None:
                if corporate.account.is_identity_declined:
                    corporate.account.is_identity_declined = False
                if corporate.account.personal is not None:
                    if corporate.account.personal.status == str(CustomerStatus.declined):
                        corporate.account.personal.status = str(CustomerStatus.documents)
                        corporate.account.personal.save()

                corporate.account.last_updated_at = corporate.last_updated_at
                corporate.account.type = AccountType.corporate
                corporate.account.save()
            corporate.status = str(CustomerStatus.submitted)
            corporate.save()

            doc_verification = DocumentVerification.objects.create(
                user=corporate.account.user,
                corporate=corporate,
                passport=passport_document,
                utilitybills=utilitybills_document,
                selfie=selfie_document,
                meta={'name': str(corporate.name),
                      'domicile_country': str(corporate.domicile_country),
                      'business_phone': str(corporate.business_phone),
                      'country': str(corporate.country),
                      'street': str(corporate.street),
                      'apartment': str(corporate.apartment),
                      'city': str(corporate.city),
                      'postcode': str(corporate.postcode),
                      'industry': str(corporate.industry),
                      'assets_origin': str(corporate.assets_origin),
                      'currency_nature': str(corporate.currency_nature),
                      'assets_origin_description': str(corporate.assets_origin_description),
                      'jcash_use': str(corporate.jcash_use),
                      'contact_firstname': str(corporate.contact_firstname),
                      'contact_lastname': str(corporate.contact_lastname),
                      'contact_middlename': str(corporate.contact_middlename),
                      'contact_birthday': str(corporate.contact_birthday),
                      'contact_nationality': str(corporate.contact_nationality),
                      'contact_residency': str(corporate.contact_residency),
                      'contact_phone': str(corporate.contact_phone),
                      'contact_email': str(corporate.contact_email),
                      'contact_street': str(corporate.contact_street),
                      'contact_apartment': str(corporate.contact_apartment),
                      'contact_city': str(corporate.contact_city),
                      'contact_postcode': str(corporate.contact_postcode)})

            doc_verification.save()
            ga_integration.on_status_registration_complete(corporate.account)
            notify.send_email_jcash_application_underway(corporate.account.user.email, corporate.account.user.pk)


class CorporateSerializer(serializers.ModelSerializer):
    """
    Serializer that takes an additional `status` argument that
    controls which fields of Corporate should be displayed.
    """

    passport = serializers.SerializerMethodField()
    utilitybills = serializers.SerializerMethodField()
    selfie = serializers.SerializerMethodField()
    success = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        # Instantiate the superclass normally
        super(CorporateSerializer, self).__init__(*args, **kwargs)

        status = self.context.get('status', '')
        if status == '':
            fields = ('success', 'name', 'domicile_country', 'business_phone')
        elif status == str(CustomerStatus.business_address):
            fields = ('success', 'country', 'street', 'apartment', 'city', 'postcode')
        elif status == str(CustomerStatus.income_info):
            fields = ('success', 'industry', 'assets_origin', 'currency_nature',
                      'assets_origin_description', 'jcash_use')
        elif status == str(CustomerStatus.primary_contact):
            fields = ('success', 'contact_firstname', 'contact_lastname', 'contact_middlename',
                      'contact_birthday', 'contact_nationality',
                      'contact_residency', 'contact_phone', 'contact_email', 'contact_street',
                      'contact_apartment', 'contact_city', 'contact_postcode')
        elif status == str(CustomerStatus.documents):
            fields = ('passport', 'utilitybills', 'selfie')
        else:
            fields = ('success',)

        included = set(fields)
        existing = set(self.fields.keys())

        for other in existing - included:
            self.fields.pop(other)

    class Meta:
        model = Corporate
        fields = ('success', 'name', 'domicile_country', 'business_phone',
                  'country', 'street', 'apartment', 'city', 'postcode',  'industry',
                  'assets_origin', 'currency_nature', 'assets_origin_description',
                  'jcash_use', 'contact_firstname', 'contact_lastname', 'contact_middlename',
                  'contact_birthday', 'contact_nationality',
                  'contact_residency', 'contact_phone', 'contact_email', 'contact_street',
                  'contact_apartment', 'contact_city', 'contact_postcode', 'passport',
                  'utilitybills', 'selfie')

    def get_passport(self, obj):
        return ''

    def get_utilitybills(self, obj):
        return ''

    def get_selfie(self, obj):
        return ''

    def get_success(self, obj):
        return True if obj else False


class CountriesListSerializer(serializers.ListSerializer):
    def to_representation(self, data):
        r = super().to_representation(data)

        return { item['name'] for item in r }


class CountriesSerializer(serializers.ModelSerializer):
    """
    Serializer for get a list of countries
    """
    class Meta:
        model = Country
        fields = ('name',)
        list_serializer_class = CountriesListSerializer


class CustomersSerializer(serializers.Serializer):
    """
    Serializer for get list of account customers
    """

    type = serializers.SerializerMethodField()
    uuid = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        fields = ('type', 'uuid', 'status')

    def get_type(self, obj):
        if isinstance(obj, Personal):
            return 'personal'
        elif isinstance(obj, Corporate):
            return 'corporate'
        else:
            return ''

    def get_uuid(self, obj):
        return obj.uuid

    def get_status(self, obj):
        return obj.status


class CheckTokenSerializer(serializers.Serializer):
    """
    Serializer that check a token.
    """
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        self._errors = {}

        # Decode the uidb64 to uid to get User object
        try:
            uid = force_text(uid_decoder(attrs['uid']))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise exceptions.ValidationError({'uid': ['Invalid value']})

        if not default_token_generator.check_token(self.user, attrs['token']):
            raise exceptions.ValidationError({'token': ['Invalid value']})

        return attrs


class ValidatePasswordSerializer(serializers.Serializer):
    """
    Serializer that validate a password.
    """
    password = serializers.CharField(required=True)

    def validate_password(self, password):
        return get_adapter().clean_password(password)
