import logging
import uuid
import binascii
import os

from allauth.account.models import EmailAddress
from django.db import models, transaction
from django.conf import settings
from django.contrib.postgres.fields import JSONField
from django.template.loader import render_to_string
from django.utils.timezone import now
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.contrib.sites.shortcuts import get_current_site


logger = logging.getLogger(__name__)


# ObjStatus
class ObjStatus:
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name


# Account statuses
class AccountStatus:
    blocked = ObjStatus('blocked', 'blocked account')
    pending = ObjStatus('pending', 'user''s documents in pending mode')
    verified = ObjStatus('verified', 'verified account')
    declined = ObjStatus('declined', 'declined account')
    created = ObjStatus('created', 'new account')


# Account model
class Account(models.Model):
    # Personal data
    first_name = models.CharField(max_length=120, null=False, blank=True)
    last_name = models.CharField(max_length=120, null=False, blank=True)
    fullname = models.CharField(max_length=120, null=False, blank=True)
    citizenship = models.CharField(max_length=120, null=False, blank=True)
    birthday = models.DateField(null=True, blank=True)
    residency = models.CharField(max_length=120, null=False, blank=True)

    # Post address
    country = models.CharField(max_length=120, null=False, blank=True)
    street = models.CharField(max_length=120, null=False, blank=True)
    town = models.CharField(max_length=120, null=False, blank=True)
    postcode = models.CharField(max_length=120, null=False, blank=True)

    terms_confirmed = models.BooleanField(default=False)

    # Modifications time
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=True)

    # States
    is_identity_verified = models.BooleanField(default=False, verbose_name='Verified')
    is_identity_declined = models.BooleanField(default=False, verbose_name='Declined')
    is_blocked = models.BooleanField(default=False, verbose_name='Blocked')

    comment = models.TextField(null=True, blank=True)
    tracking = JSONField(blank=True, default=dict)
    onfido_applicant_id = models.CharField(max_length=200, null=True, blank=True)

    rel_applications = 'applications'
    rel_documents = 'documents'
    rel_addresses = 'addresses'

    # Relationships
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    class Meta:
        db_table = 'account'

    def reset_verification_state(self, fullreset=True):
        self.is_identity_verified = False
        self.is_identity_declined = False

        if fullreset:
            self.document_type = ''
            self.document_url = ''
            self.first_name = ''
            self.last_name = ''
            self.date_of_birth = None
            self.residency = ''
            self.country = ''
            self.citizenship = ''
        self.save()

    def block_account(self):
        self.is_blocked = True
        self.save()

    def approve_verification(self):
        self.is_identity_verified = True
        self.is_identity_declined = False
        self.save()

    def decline_verification(self):
        self.is_identity_verified = False
        self.is_identity_declined = True
        self.save()
        # notify.send_email_kyc_account_rejected(self.user.email if self.user else None,
        # self.user.id if self.user else None) # Todo:

    @classmethod
    def is_user_email_confirmed(cls, user):
        try:
            email = EmailAddress.objects.get(email=user.email)
            return email.verified
        except EmailAddress.DoesNotExist:
            logger.error('No EmailAddress for user %s!!', user.username)
            return False

    def __str__(self):
        return '{} {}'.format(self.first_name, self.last_name)


class DocumentHelper:
    @classmethod
    def get_document_filename_extension(cls, filename):
        if len(filename.split(".")) > 1:
            return filename.split(".")[-1]
        else:
            return "unknown"

    @classmethod
    def unique_document_filename(cls,  document, filename):
        extension = cls.get_document_filename_extension(filename)
        return "{}.{}".format(uuid.uuid4(), extension)


# Document model
class Document(models.Model):
    image = models.FileField('uploaded document', upload_to=DocumentHelper.unique_document_filename)  # stores the uploaded documents
    ext = models.CharField(max_length=20, null=False, blank=True)
    type = models.CharField(max_length=20, null=False, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    onfido_document_id = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_id = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_status = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_result = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_created = models.DateTimeField(null=True, blank=True)
    verification_started_at = models.DateTimeField(null=True, blank=True)
    verification_attempts = models.IntegerField(default=0)

    # Relationships
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=False, null=False, related_name=Account.rel_documents)

    class Meta:
        db_table = 'document'


# Address model
class Address(models.Model):
    address = models.CharField(unique=True, max_length=255)
    type = models.CharField(max_length=10)
    is_verified = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)
    is_removed = models.BooleanField(default=False)
    is_allowed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    meta = JSONField(default=dict)  # This field type is a guess.

    rel_verifies = 'verifies'
    rel_applications = 'applications'

    # Relationships
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=False, null=False, related_name=Account.rel_addresses)

    class Meta:
        db_table = 'address'

    def __str__(self):
        return '{}: {}'.format(self.type, self.address)


# AddressMessage
class AddressVerify(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sig = models.CharField(unique=True, max_length=255, null=True, blank=True)
    message = models.CharField(unique=False, max_length=1024)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    # Relationships
    address = models.ForeignKey(Address, on_delete=models.DO_NOTHING,
                                blank=False, null=False, related_name=Address.rel_verifies)

    class Meta:
        db_table = 'address_verify'


class NotificationType:
    # Registration
    account_created         = 'account_created'
    account_email_confirmed = 'account_email_confirmed'
    password_change_request = 'password_change_request'
    password_changed        = 'password_changed'


class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=True, null=True, related_name='notifications')

    type = models.CharField(max_length=100)
    email = models.CharField(max_length=120, null=False)
    created = models.DateTimeField(auto_now_add=True)
    sended = models.DateTimeField(null=True)
    is_sended = models.BooleanField(default=False)
    rendered_message = models.TextField(null=True, blank=True)

    meta = JSONField(default=dict)  # This field type is a guess.

    class Meta:
        db_table = 'notification'

    notification_keys = {
        NotificationType.account_created: 'registration_01',
        NotificationType.account_email_confirmed: 'registration_02',
        NotificationType.password_change_request: 'account_01_01',
        NotificationType.password_changed: 'account_01_02',
    }

    notification_subjects = {
        'account_01_01': 'Password change request',
        'account_01_02': 'Your password was updated',
        'registration_01': 'Verify your email address',
        'registration_02': 'Accessing your jCash',
    }

    def __str__(self):
        return '{} [{}, {}]'.format(self.type, self.created, self.is_sended)

    @classmethod
    def get_subject(cls, type, data):
        return cls.notification_subjects[cls.get_key(type)].format(**data)

    @classmethod
    def get_template(cls, type):
        return "{}.html".format(cls.get_key(type))

    @classmethod
    def get_key(cls, type):
        return cls.notification_keys[type]

    @classmethod
    def get_body(cls, type, data):
        return render_to_string(cls.get_template(type), data)


class Affiliate(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING)
    event = models.CharField(max_length=20)
    url = models.CharField(max_length=300, null=False)
    created = models.DateTimeField(auto_now_add=True)
    sended = models.DateTimeField(null=True)
    status = models.IntegerField(blank=True, null=True)
    meta = JSONField(default=dict)  # This field type is a guess.

    class Meta:
        db_table = 'affiliate'


class OperationError(Exception):
    """
    Operation execution error
    """

# Currency
class Currency(models.Model):
    display_name = models.CharField(max_length=10)
    symbol = models.CharField(max_length=10)
    exchanger_address = models.CharField(max_length=255, blank=True, null=True)
    view_address = models.CharField(unique=True, max_length=255, blank=True, null=True)
    controller_address = models.CharField(unique=True, max_length=255, blank=True, null=True)
    license_registry_address = models.CharField(unique=True, max_length=255, blank=True, null=True)
    is_erc20_token = models.BooleanField(default=False)
    balance = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
    abi = JSONField(default=dict)
    round_digits = models.IntegerField(null=False, default=8)

    rel_base_currencies = 'base_currencies'
    rel_reciprocal_currencies = 'reciprocal_currencies'

    class Meta:
        db_table = 'currency'


# CurrencyPair
class CurrencyPair(models.Model):
    display_name = models.CharField(max_length=10)
    symbol = models.CharField(max_length=10)
    base_currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING, related_name=Currency.rel_base_currencies)
    reciprocal_currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING, related_name=Currency.rel_reciprocal_currencies)
    is_exchangeable = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_buyable = models.BooleanField(default=False)
    is_sellable = models.BooleanField(default=False)
    buy_fee_percent = models.FloatField(default=0.0)
    sell_fee_percent = models.FloatField(default=0.0)

    rel_currency_pair_rates = 'currency_pair_rates'
    rel_applications = 'applications'

    class Meta:
        db_table = 'currency_pair'


# CurrencyPairRate
class CurrencyPairRate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    currency_pair = models.ForeignKey(CurrencyPair, on_delete=models.DO_NOTHING, related_name=CurrencyPair.rel_currency_pair_rates)
    buy_price = models.FloatField()
    sell_price = models.FloatField()
    created_at = models.DateTimeField()
    meta = JSONField(default={})

    rel_applications = 'applications'

    class Meta:
        db_table = 'currency_pair_rate'


# AccountAddress
class AccountAddress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING)
    address = models.CharField(unique=True, max_length=255)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'account_address'


# ApplicationStatus
class ApplicationStatus:
    created = ObjStatus('created', 'new application')
    cancelled = ObjStatus('cancelled', 'user clicked back')
    waiting = ObjStatus('waiting', 'waiting for user tx')
    confirming = ObjStatus('confirming', 'we received unexpected value (and CAN go further)')
    converting = ObjStatus('converting', 'we sent tx but it was not mined')
    converted = ObjStatus('converted', 'converted, tx is mined')
    refunding = ObjStatus('refunding', 'clicked "No, refund" (tx is in progress, not mined yet)')
    refunded = ObjStatus('refunded', 'refunded, tx is mined')


# Application
class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, models.DO_NOTHING,
                             blank=True, null=True, related_name=Account.rel_applications)
    address = models.ForeignKey(Address,
                                on_delete=models.DO_NOTHING,
                                related_name=Address.rel_applications)
    currency_pair = models.ForeignKey(CurrencyPair,
                                      on_delete=models.DO_NOTHING,
                                      related_name=CurrencyPair.rel_applications)
    currency_pair_rate = models.ForeignKey(CurrencyPairRate,
                                           on_delete=models.DO_NOTHING,
                                           related_name=CurrencyPair.rel_applications)
    exchanger_address = models.CharField(max_length=255, blank=True, null=True)
    base_currency = models.CharField(max_length=10)
    reciprocal_currency = models.CharField(max_length=10)
    rate = models.FloatField()
    base_amount = models.FloatField()
    reciprocal_amount = models.FloatField()

    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_reverse = models.BooleanField(default=False)
    status = models.CharField(max_length=10, default=str(ApplicationStatus.created))
    meta = JSONField(default=dict)

    rel_exchanges = 'exchanges'
    rel_refundes = 'refundes'
    rel_incoming_txs = 'incoming_txs'

    class Meta:
        db_table = 'application'


# TransactionStatus
class TransactionStatus:
    not_confirmed = 'not_confirmed'
    confirmed = 'confirmed'
    pending = 'pending'
    fail = 'fail'
    success = 'success'
    rejected = 'rejected'


# IncomingTransaction
class IncomingTransaction(models.Model):
    transaction_id = models.CharField(max_length=120, null=False, blank=False, unique=True)
    application = models.ForeignKey(Application, models.DO_NOTHING, related_name=Application.rel_incoming_txs, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    mined_at = models.DateTimeField(null=True, blank=True)
    block_height = models.IntegerField(blank=True, null=True)
    from_address = models.CharField(max_length=120, null=True, blank=True)
    to_address = models.CharField(max_length=120, null=True, blank=True)
    value = models.FloatField(default=0)
    status = models.CharField(max_length=20, default=TransactionStatus.not_confirmed)
    is_linked = models.BooleanField(default=False)
    meta = JSONField(default=dict)

    rel_refundes = 'refundes'
    rel_exchanges = 'exchanges'

    class Meta:
        db_table = 'incoming_transaction'


# Exchange
class Exchange(models.Model):
    transaction_id = models.CharField(max_length=120, null=True, blank=True)
    application = models.ForeignKey(Application, models.DO_NOTHING, related_name=Application.rel_exchanges)
    incoming_transaction = models.ForeignKey(IncomingTransaction, models.DO_NOTHING,
                                             related_name=IncomingTransaction.rel_refundes, null=True)
    to_address = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField()
    mined_at = models.DateTimeField(null=True, blank=True)
    block_height = models.IntegerField(blank=True, null=True)
    value = models.FloatField(default=0)
    status = models.CharField(max_length=20, default=TransactionStatus.not_confirmed)
    meta = JSONField(default=dict)

    class Meta:
        db_table = 'exchange'


# Refund
class Refund(models.Model):
    transaction_id = models.CharField(max_length=120, null=True, blank=True)
    application = models.ForeignKey(Application, models.DO_NOTHING, related_name=Application.rel_refundes, null=True)
    incoming_transaction = models.ForeignKey(IncomingTransaction, models.DO_NOTHING,
                                             related_name=IncomingTransaction.rel_exchanges, null=True)
    to_address = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField()
    mined_at = models.DateTimeField(null=True, blank=True)
    block_height = models.IntegerField(blank=True, null=True)
    value = models.FloatField(default=0)
    status = models.CharField(max_length=20, default=TransactionStatus.not_confirmed)
    meta = JSONField(default=dict)

    class Meta:
        db_table = 'refund'


# SystemEvents
class SystemEvents(models.Model):
    SE_ACCOUNT_REG_DATA_FILLED   = 'account_reg_data_filled'
    SE_ACCOUNT_APPROVED          = 'account_approved'
    SE_ACCOUNT_REJECTED          = 'account_rejected'
    SE_ACCOUNT_DOCS_UPPLOADED    = 'account_docs_uploaded'
    SE_DOCUMENT_UPLOADED         = 'document_uploaded'
    SE_APPLICATION_CREATED       = 'application_created'
    SE_APPLICATION_REJECTED      = 'application_rejected'
    SE_APPLICATION_APPROVED      = 'application approved'
    SE_APPLICATION_REFUNDED      = 'application_refunded'
    SE_TRANSACTION_RECEIVED      = 'transaction_received'
    SE_EXCHANGE_CANCELLED        = 'exchane_cancelled'
    SE_EXCHANGE_STARTED          = 'exchange_started'
    SE_EXCHANGE_FAILED           = 'exchange_failed'
    SE_EXCHANGE_SUCCESSED        = 'exchange_successed'
    SE_NOTIFICATION_CREATED      = 'notification_created'
    SE_NOTIFICATION_SENDED       = 'notification_sended'

    SE_CHOICES = [
        (SE_ACCOUNT_REG_DATA_FILLED, 'account_reg_data_filled'),
        (SE_ACCOUNT_APPROVED, 'account_approved'),
        (SE_ACCOUNT_REJECTED, 'account_rejected'),
        (SE_ACCOUNT_DOCS_UPPLOADED, 'account_docs_uploaded'),
        (SE_DOCUMENT_UPLOADED, 'document_uploaded'),
        (SE_APPLICATION_CREATED, 'application_created'),
        (SE_APPLICATION_REJECTED, 'application_rejected'),
        (SE_APPLICATION_APPROVED, 'application approved'),
        (SE_APPLICATION_REFUNDED, 'application_refunded'),
        (SE_TRANSACTION_RECEIVED, 'transaction_received'),
        (SE_EXCHANGE_CANCELLED, 'exchane_cancelled'),
        (SE_EXCHANGE_STARTED, 'exchange_started'),
        (SE_EXCHANGE_FAILED, 'exchange_failed'),
        (SE_EXCHANGE_SUCCESSED, 'exchange_successed'),
        (SE_NOTIFICATION_CREATED, 'notification_created'),
        (SE_NOTIFICATION_SENDED, 'notification_sended'),
    ]

    handlers = {
        #SE_APPLICATION_CREATED: ApplicationCreatedHandler(),
        #SE_APPLICATION_REJECTED: ApplicationRejectedHandler(),
    }

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING)
    event_type = models.CharField(max_length=20, choices=SE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    params = JSONField(default=dict)

    class Meta:
        db_table = 'systemevents'

    @classmethod
    def create_systemevent(cls, event_type, user, params):
        with transaction.atomic():
            op = cls.objects.create(
                event_type=event_type,
                user=user,
                params=params
            )
            return op
