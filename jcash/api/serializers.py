import logging
from datetime import datetime
from dateutil.tz import tzlocal

from django.db import transaction
from django import forms
from django.db.models import Sum
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, password_validation
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import ugettext_lazy as _
from django.contrib.sites.models import Site
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


from jcash.api.models import (
    Address, Account, Document,
    DocumentHelper, AddressVerify, Application, CurrencyPair, ApplicationStatus,
    IncomingTransaction, Exchange, Refund, AccountStatus
)
from jcash.commonutils import eth_sign, eth_address
from jcash.commonutils.notify import send_email_reset_password


logger = logging.getLogger(__name__)

RECAPTCA_API_URL = 'https://www.google.com/recaptcha/api/siteverify'

class CaptchaHelper():
    @classmethod
    def validate_captcha(cls, captcha_token):
        if settings.RECAPTCHA_ENABLED is not True:
            return True
        try:
            r = requests.post(
                RECAPTCA_API_URL,
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

                    logger.error('Invalid reCaptcha secret key detected')
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


class AccountSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    is_email_confirmed = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    success = serializers.SerializerMethodField()

    class Meta:
        model = Account
        fields = ('success', 'username', 'first_name', 'last_name', 'birthday',
                  'citizenship', 'residency', 'is_identity_verified',
                  'is_identity_declined', 'is_email_confirmed', 'status')
        read_only_fields = ('is_identity_verified', 'is_identity_declined', 'is_email_confirmed')

    def get_success(self, obj):
        return True if obj else False

    def get_username(self, obj):
        return obj.user.email

    def get_is_email_confirmed(self, obj):
        return Account.is_user_email_confirmed(obj.user)

    def get_status(self, obj):
        def is_personal_data_filled(obj):
            fields = [obj.first_name, obj.last_name, obj.birthday,
                      obj.residency, obj.citizenship]
            return True if all(fields) else False

        if not obj:
            return ''
        elif obj.is_blocked:
            return str(AccountStatus.blocked)
        elif is_personal_data_filled(obj) and \
            obj.user.documents.count() >= 2 and \
            not obj.is_identity_verified and \
            not obj.is_identity_declined:
            return str(AccountStatus.pending)
        elif is_personal_data_filled(obj) and \
            obj.is_identity_verified and \
            not obj.is_identity_declined:
            return str(AccountStatus.verified)
        elif is_personal_data_filled(obj) and \
            not obj.is_identity_verified and \
            obj.is_identity_declined:
            return str(AccountStatus.declined)
        else:
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
        # ga_integration.on_status_new(account)
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
            if user.account.is_blocked:
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
        activate_url = '{protocol}://{domain}/#/auth/recovery/confirm/{uid}/{token}'.format(**context)
        logger.info("{} {}".format(to_email, activate_url))
        send_email_reset_password(to_email, activate_url, None)


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
        try:
            user = UserModel._default_manager.get(email=email)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise exceptions.ValidationError(_('Invalid email.'))
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return email

    def validate_captcha(self, captcha_token):
        CaptchaHelper.validate_captcha(captcha_token)

    def save(self):
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
            raise exceptions.ValidationError({'uid': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs['token']):
            raise exceptions.ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
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
        "rate": 1810.0,
        "is_active": true
        "status": "created",
    }]
    """
    app_uuid = serializers.SerializerMethodField()
    incoming_tx_id = serializers.SerializerMethodField()
    incoming_tx_value = serializers.SerializerMethodField()
    outgoing_tx_id = serializers.SerializerMethodField()
    outgoing_tx_value = serializers.SerializerMethodField()
    source_address = serializers.SerializerMethodField()

    class Meta:
        model = Application
        fields = ('app_uuid', 'created_at', 'incoming_tx_id', 'outgoing_tx_id',
                  'incoming_tx_value', 'outgoing_tx_value', 'source_address', 'exchanger_address',
                  'base_currency', 'base_amount', 'reciprocal_currency',
                  'reciprocal_amount', 'rate', 'is_active', 'status')

    def get_app_uuid(self, obj):
        return obj.id

    def get_source_address(self, obj):
        return obj.address.address

    def get_incoming_tx(self, obj):
        try:
            txs = IncomingTransaction.objects.filter(application=obj)
            return txs[0] if len(txs)>0 else None
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
        if obj.status == str(ApplicationStatus.converting) or \
                obj.status == str(ApplicationStatus.converted):
            try:
                txs = Exchange.objects.filter(application=obj)
                return txs[0] if len(txs) > 0 else None
            except:
                return None
        elif obj.status == str(ApplicationStatus.refunding) or \
                obj.status == str(ApplicationStatus.refunded):
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

        address_verify = AddressVerify.objects.filter(id=message_uuid).first()
        if not address_verify:
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
    base_amount = serializers.FloatField(required=True)


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
        return "I, {} {}, hereby confirm that I and only I own and have access to the private key of the address {}. Date: {} UTC" \
            .format(address.user.account.first_name, address.user.account.last_name,
                    address.address, timezone.now().strftime('%Y %B %d %I:%M %p'))

    def save(self, user):
        address = None
        try:
            address = Address.objects.get(address__iexact=self.validated_data['address'], user=user)
        except Address.DoesNotExist:
            pass
        with transaction.atomic():
            if not address:
                address = Address.objects.create(user=user, **self.validated_data)
            address_verify = AddressVerify.objects.create(address=address,
                                                          message=self.generate_message(address))
        self.validated_data['message'] = address_verify.message
        self.validated_data['uuid'] = address_verify.id
        self.validated_data['success'] = True

    def validate(self, attrs):
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

        attrs['address'] = address
        attrs['type'] = type
        attrs['is_verified'] = False
        return attrs


class ApplicationSerializer(serializers.Serializer):
    address = serializers.CharField(required=False)
    base_currency = serializers.CharField(required=True)
    rec_currency = serializers.CharField(required=True)
    base_amount = serializers.FloatField(required=True)
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
        base_amount_attr = attrs.get('base_amount')
        rate_uuid = attrs.get('uuid')

        user_addresses = Address.objects.filter(user=user, is_verified=True)
        if not address_attr and len(user_addresses) > 1:
            raise serializers.ValidationError(_('"address" not specified.'))
        if address_attr and not user_addresses.filter(address=address_attr).first():
            raise serializers.ValidationError(_('wrong "address".'))
        address = user_addresses[0] if len(user_addresses)==1 else user_addresses.filter(address=address_attr)

        if not address:
            raise serializers.ValidationError(_('specified "address" not found.'))

        attrs['address_id'] = address.pk

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

        attrs['exchanger_address'] = currency_pair.base_currency.exchanger_address if is_reverse_operation else \
            currency_pair.reciprocal_currency.exchanger_address

        attrs['currency_pair_id'] = currency_pair.pk

        currency_pair_rate = currency_pair.currency_pair_rates.filter(id=rate_uuid).first()

        if not currency_pair_rate:
            raise serializers.ValidationError(_('Currency price does not exists.'))

        if currency_pair_rate.currency_pair.pk != currency_pair.pk:
            raise serializers.ValidationError(_('Wrong currency price.'))

        #!!if abs((datetime.now(tzlocal()) - currency_pair_rate.created_at).seconds) > 10*60:
        #!!    raise serializers.ValidationError(_('Сurrency price is out of date.'))

        currency_pair_rate_price = currency_pair_rate.sell_price if is_reverse_operation else currency_pair_rate.buy_price
        if is_reverse_operation:
            currency_pair_rate_price = 1.0 / currency_pair_rate_price

        attrs['currency_pair_rate_id'] = currency_pair_rate.pk
        attrs['rate'] = currency_pair_rate_price
        attrs['reciprocal_amount'] = base_amount_attr * currency_pair_rate_price

        return attrs

    def save(self):
        user = self.context['user']
        with transaction.atomic():
            application = Application.objects.create(user=user,
                                                     is_active=True,
                                                     address_id=self.validated_data['address_id'],
                                                     currency_pair_id=self.validated_data['currency_pair_id'],
                                                     currency_pair_rate_id=self.validated_data['currency_pair_rate_id'],
                                                     base_currency=self.validated_data['base_currency'],
                                                     reciprocal_currency=self.validated_data['rec_currency'],
                                                     rate=self.validated_data['rate'],
                                                     base_amount=self.validated_data['base_amount'],
                                                     reciprocal_amount=self.validated_data['reciprocal_amount'],
                                                     exchanger_address=self.validated_data['exchanger_address'])
            application.save()
            self.validated_data['application_id'] = application.pk


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
                     self.application.status == str(ApplicationStatus.converted)):
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
                self.application.is_active = False
                self.application.save()
