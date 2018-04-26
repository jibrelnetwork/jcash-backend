import logging
from datetime import datetime

from django.db import transaction
from django.db.models import Sum
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _
from django.contrib.sites.models import Site
from django.utils import timezone, dateformat
from allauth.account import app_settings as allauth_settings
from allauth.utils import email_address_exists
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from rest_auth.serializers import PasswordResetSerializer, PasswordResetForm
from rest_framework import serializers, exceptions
from rest_framework.fields import CurrentUserDefault
import requests

from jcash.api.models import (
    Address, Account, is_user_email_confirmed, Document,
    DocumentHelper, AddressVerify
)
from jcash.api import tasks


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

    class Meta:
        model = Account
        fields = ('username', 'first_name', 'last_name', 'birthday',
                  'citizenship', 'residency', 'terms_confirmed',
                  'is_identity_verified', 'is_identity_declined', 'is_email_confirmed')
        read_only_fields = ('is_identity_verified', 'is_identity_declined', 'is_email_confirmed')

    def get_username(self, obj):
        return obj.user.email

    def get_is_email_confirmed(self, obj):
        return is_user_email_confirmed(obj.user)


class RegisterSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    password_confirm = serializers.CharField(required=True, write_only=True)
    captcha = serializers.CharField(required=True, write_only=True)
    tracking = serializers.JSONField(write_only=True, required=False, default=dict)

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
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError(_("The two password fields didn't match."))
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
    email = serializers.EmailField(required=True, allow_blank=False)
    password = serializers.CharField(style={'input_type': 'password'})
    captcha = serializers.CharField(required=True, write_only=True)

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
        activate_url = '{protocol}://{domain}/#/welcome/password/change/{uid}/{token}'.format(**context)
        #!!send_email_reset_password(to_email, activate_url, None)


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

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return value

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


class ResendEmailConfirmationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, allow_blank=False)


class OperationConfirmSerializer(serializers.Serializer):
    operation_id = serializers.CharField()
    token = serializers.CharField()


class DocumentSerializer(serializers.Serializer):
    passport = serializers.FileField(required=True)
    utilitybills = serializers.FileField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    birthday = serializers.DateField(required=True)
    citizenship = serializers.CharField(required=True)
    residency = serializers.CharField(required=True)
    terms_confirmed = serializers.BooleanField(required=True)

    class Meta:
        model = Document
        fields = ('passport', 'utilitybills', 'first_name'
                  'last_name', 'birthday', 'citizenship',
                  'residency', 'terms_confirmed')

    def save(self, account):
        current_site = Site.objects.get_current()

        with transaction.atomic():
            passport_document = Document.objects.create(user=account.user)
            passport_document.image = self.validated_data['passport']
            passport_document.type = 'passport'
            passport_document.url = "https://{}{}".format("saleapi.jibrel.network", passport_document.image.url)
            passport_document.ext = DocumentHelper.get_document_filename_extension(passport_document.image.name)
            passport_document.save()
            utilitybills_document = Document.objects.create(user=account.user)
            utilitybills_document.image = self.validated_data['utilitybills']
            utilitybills_document.type = 'utilitybills'
            utilitybills_document.url = "https://{}{}".format("saleapi.jibrel.network", utilitybills_document.image.url)
            utilitybills_document.ext = DocumentHelper.get_document_filename_extension(utilitybills_document.image.name)
            utilitybills_document.save()
            account.first_name = self.validated_data['first_name']
            account.last_name = self.validated_data['last_name']
            account.citizenship = self.validated_data['citizenship']
            account.birthday = self.validated_data['birthday']
            account.residency = self.validated_data['residency']
            account.terms_confirmed = self.validated_data['terms_confirmed']
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


class AddressVerifySerializer(serializers.Serializer):
    address = serializers.CharField(required=True, allow_blank=False)
    sig = serializers.CharField(required=True, allow_blank=False)
    message_uuid = serializers.CharField(required=True, allow_blank=False)

    class Meta:
        model = AddressVerify
        fields = ('address', 'sig', 'message_uuid')


class CurrencyRateSerializer(serializers.Serializer):
    base_currency = serializers.CharField(required=True, allow_blank=False)
    rec_currency = serializers.CharField(required=True, allow_blank=False)
    base_amount = serializers.FloatField(required=True)


class CurrencySerializer(serializers.Serializer):
    pass


class AddressSerializer(serializers.Serializer):
    address = serializers.CharField(required=True, allow_blank=False)
    type = serializers.CharField(required=True, allow_blank=False)

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

    def validate(self, attrs):
        address = attrs.get('address')
        type = attrs.get('type')

        if type and type=='eth' and address:
            #!!if not ethaddress_verify.is_valid_address(address):
            #!!    raise serializers.ValidationError(_('Ethereum address is not valid.'))
            pass
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


class ApplicationRefundSerializer(serializers.Serializer):
    app_uuid = serializers.CharField(required=True, allow_blank=False)


class ApplicationConfirmSerializer(serializers.Serializer):
    app_uuid = serializers.CharField(required=True, allow_blank=False)
