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

from jcash.commonutils import notify


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
    email_confirmation = ObjStatus('email_confirmation', 'email confirmation required')
    created = ObjStatus('created', 'new account')


# Account types
class AccountType:
    personal = 'personal'
    corporate = 'corporate'
    beneficiary = 'beneficiary'


# Account model
class Account(models.Model):
    # Account type
    type = models.CharField(max_length=20, null=False, blank=True, default='')
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

    rel_applications = 'applications'
    rel_documents = 'documents'
    rel_addresses = 'addresses'
    rel_personal = 'personal'
    rel_corporate = 'corporate'
    rel_documentverification = 'documentverification'
    rel_licenseaddress = 'licenseaddress'

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

    def unblock_account(self):
        self.is_blocked = False
        self.save()

    def approve_verification(self):
        with transaction.atomic():
            self.is_identity_verified = True
            self.is_identity_declined = False
            self.save()
            doc_verification = None
            customer = self.get_customer()
            if customer:
                customer.status = str(CustomerStatus.submitted)
                customer.save()
                if hasattr(customer, 'document_verifications') and \
                        customer.document_verifications.count() > 0:
                    doc_verification = customer.document_verifications.latest('created_at')
            if doc_verification:
                doc_verification.is_identity_verified = True
                doc_verification.is_identity_declined = False
                doc_verification.save()

            notify.send_email_kyc_account_approved(self.user.email if self.user else None,
                                                   self.user.id if self.user else None)

    def get_customer(self):
        personal = None
        corporate = None
        if hasattr(self, 'personal'):
            personal = self.personal
        if hasattr(self, 'corporate'):
            corporate = self.corporate

        if corporate and personal:
            if personal.last_updated_at >= corporate.last_updated_at:
                return personal
            else:
                return corporate
        elif corporate:
            return corporate
        elif personal:
            return personal
        else:
            return None

    def decline_verification(self, reason):
        with transaction.atomic():
            self.is_identity_verified = False
            self.is_identity_declined = True
            self.save()
            doc_verification = None
            customer = self.get_customer()
            if customer:
                customer.status = str(CustomerStatus.declined)
                customer.save()
                if hasattr(customer, 'document_verifications') and \
                        customer.document_verifications.count() > 0:

                    doc_verification = customer.document_verifications.latest('created_at')
            if doc_verification:
                doc_verification.is_identity_verified = False
                doc_verification.is_identity_declined = True
                doc_verification.comment = reason
                doc_verification.save()

            notify.send_email_kyc_account_rejected(self.user.email if self.user else None,
                                                   reason,
                                                   self.user.id if self.user else None)

    @classmethod
    def is_user_email_confirmed(cls, user):
        try:
            email = EmailAddress.objects.get(email=user.email)
            return email.verified
        except EmailAddress.DoesNotExist:
            logger.error('No EmailAddress for user %s!!', user.username)
            return False

    @classmethod
    def check_exchange_rights(cls, user):
        if Account.is_user_email_confirmed(user) is False:
            return False, "Please confirm the e-mail"
        if not hasattr(user, 'account'):
            return False, "Please fill KYC data"
        if user.account.is_blocked:
            return False, "Account is blocked"
        if user.account.is_identity_declined:
            return False, "KYC rejected"
        if not user.account.is_identity_verified:
            return False, "KYC data is not verified yet"
        return True, None

    @classmethod
    def check_kyc_rights(cls, user):
        if Account.is_user_email_confirmed(user) is False:
            return False, "Please confirm the e-mail"
        if hasattr(user, 'account'):
            if user.account.is_blocked:
                return False, "Account is blocked"
            if not user.account.is_identity_declined and \
                    not user.account.is_identity_verified and \
                    hasattr(user, Account.rel_documentverification) and \
                    user.documentverification.count() > 0:
                return False, "KYC data is not verified yet"
        return True, None

    def __str__(self):
        return '{} {}'.format(self.id, self.user.username if self.user else '')


# Country types
class CountryType:
    residential = 'residential'
    citizenship = 'citizenship'


# Country
class Country(models.Model):
    type = models.CharField(max_length=20, null=False, blank=False, verbose_name='Type')
    name = models.CharField(max_length=120, null=False, blank=False, verbose_name='Country name')
    is_removed = models.BooleanField(default=False, verbose_name='Removed')


# Personal fields length
class PersonalFieldLength:
    fullname = 255
    nationality = 120
    phone = 120
    email = 120
    country = 120
    street = 120
    apartment = 120
    city = 120
    postcode = 120
    profession = 120
    income_source = 255
    assets_origin = 255
    jcash_use = 255


# Customer statuses
class CustomerStatus:
    address = ObjStatus('address', 'address info required (personal)')
    business_address = ObjStatus('business_address', 'business address info required (corporate)')
    income_info = ObjStatus('income_info', 'income info required (personal, corporate)')
    primary_contact = ObjStatus('primary_contact', 'primary contact info required (corporate)')
    documents = ObjStatus('documents', 'documents required (personal, corporate)')
    submitted = ObjStatus('submitted', 'all fields submitted (personal, corporate)')
    declined = ObjStatus('declined', 'customer declined (personal, corporate)')


class Personal(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Contact information
    fullname = models.CharField(max_length=PersonalFieldLength.fullname, null=False, blank=True)
    nationality = models.CharField(max_length=PersonalFieldLength.nationality, null=False, blank=True)
    birthday = models.DateField(null=True, blank=True)
    phone = models.CharField(max_length=PersonalFieldLength.phone, null=False, blank=True)
    email = models.CharField(max_length=PersonalFieldLength.email, null=False, blank=True)

    # Residential / address
    country = models.CharField(max_length=PersonalFieldLength.country, null=False, blank=True)
    street = models.CharField(max_length=PersonalFieldLength.street, null=False, blank=True)
    apartment = models.CharField(max_length=PersonalFieldLength.apartment, null=False, blank=True)
    city = models.CharField(max_length=PersonalFieldLength.city, null=False, blank=True)
    postcode = models.CharField(max_length=PersonalFieldLength.postcode, null=False, blank=True)

    # Income information
    profession = models.CharField(max_length=PersonalFieldLength.profession, null=False, blank=True)
    income_source = models.CharField(max_length=PersonalFieldLength.income_source, null=False, blank=True)
    assets_origin = models.CharField(max_length=PersonalFieldLength.assets_origin, null=False, blank=True)
    jcash_use = models.CharField(max_length=PersonalFieldLength.jcash_use, null=False, blank=True)

    # Modifications time
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=True)

    status = models.CharField(max_length=20, default='')
    onfido_applicant_id = models.CharField(max_length=200, null=True, blank=True)

    # Relationships
    account = models.OneToOneField(Account, on_delete=models.DO_NOTHING,
                                   null=True, related_name=Account.rel_personal)

    rel_documents = 'documents'
    rel_document_verifications = 'document_verifications'


# Corporate fields length
class CorporateFieldLength:
    name = 255
    phone = 120
    email = 120
    country = 120
    fullname = 255
    street = 120
    apartment = 120
    city = 120
    postcode = 120
    profession = 120
    assets_origin = 255
    assets_origin_description = 255
    jcash_use = 255
    industry = 255
    currency_nature = 255


class Corporate(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Company information
    name = models.CharField(max_length=CorporateFieldLength.name,
                            null=False, blank=True)
    domicile_country = models.CharField(max_length=CorporateFieldLength.country,
                                        null=False, blank=True)
    business_phone = models.CharField(max_length=CorporateFieldLength.phone,
                                      null=False, blank=True)
    business_email = models.EmailField(max_length=CorporateFieldLength.email,
                                       null=False, blank=True)

    # Business address.
    country = models.CharField(max_length=CorporateFieldLength.country,
                               null=False, blank=True)
    street = models.CharField(max_length=CorporateFieldLength.street,
                              null=False, blank=True)
    apartment = models.CharField(max_length=CorporateFieldLength.apartment,
                                 null=False, blank=True)
    city = models.CharField(max_length=CorporateFieldLength.city,
                            null=False, blank=True)
    postcode = models.CharField(max_length=CorporateFieldLength.postcode,
                                null=False, blank=True)

    # Income information
    industry = models.CharField(max_length=CorporateFieldLength.industry, null=False, blank=True)
    assets_origin = models.CharField(max_length=CorporateFieldLength.assets_origin, null=False, blank=True)
    currency_nature = models.CharField(max_length=CorporateFieldLength.currency_nature, null=False, blank=True)

    assets_origin_description = models.CharField(max_length=CorporateFieldLength.assets_origin_description,
                                                  null=False, blank=True)
    jcash_use = models.CharField(max_length=CorporateFieldLength.jcash_use, null=False, blank=True)

    # Primary contact
    contact_fullname = models.CharField(max_length=CorporateFieldLength.fullname, null=False, blank=True)
    contact_birthday = models.DateField(null=True, blank=True)
    contact_nationality = models.CharField(max_length=CorporateFieldLength.country, null=False, blank=True)
    contact_residency = models.CharField(max_length=CorporateFieldLength.country, null=False, blank=True)
    contact_phone = models.CharField(max_length=CorporateFieldLength.phone, null=False, blank=True)
    contact_email = models.CharField(max_length=CorporateFieldLength.email, null=False, blank=True)
    contact_street = models.CharField(max_length=CorporateFieldLength.street, null=False, blank=True)
    contact_apartment = models.CharField(max_length=CorporateFieldLength.apartment, null=False, blank=True)
    contact_city = models.CharField(max_length=CorporateFieldLength.city, null=False, blank=True)
    contact_postcode = models.CharField(max_length=CorporateFieldLength.postcode, null=False, blank=True)

    # Modifications time
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=True)

    status = models.CharField(max_length=20, default='')
    onfido_applicant_id = models.CharField(max_length=200, null=True, blank=True)

    # Relationships
    account = models.OneToOneField(Account, on_delete=models.DO_NOTHING,
                                   null=True, related_name=Account.rel_corporate)

    rel_documents = 'documents'
    rel_document_verifications = 'document_verifications'


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


class DocumentGroup:
    personal = 'personal'
    corporate = 'corporate'


class DocumentType:
    passport = 'passport'
    utilitybills = 'utilitybills'
    selfie = 'selfie'


# Document model
class Document(models.Model):
    image = models.FileField('uploaded document', upload_to=DocumentHelper.unique_document_filename)  # stores the uploaded documents
    ext = models.CharField(max_length=20, null=False, blank=True)
    type = models.CharField(max_length=20, null=False, blank=True)
    group = models.CharField(max_length=20, null=False, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Relationships
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=False, null=False, related_name=Account.rel_documents)

    personal = models.ForeignKey(Personal, on_delete=models.DO_NOTHING,
                                 related_name=Personal.rel_documents, null=True)
    corporate = models.ForeignKey(Corporate, on_delete=models.DO_NOTHING,
                                  related_name=Corporate.rel_documents, null=True)
    onfido_document_id = models.CharField(max_length=200, null=True, blank=True)

    rel_passport_verification = 'passport_verification'
    rel_utilitybills_verification = 'utilitybills_verification'
    rel_selfie_verification = 'selfie_verification'

    class Meta:
        db_table = 'document'


class DocumentVerificationStatus:
    created = 'created'
    submitted = 'submitted'
    upload_issue = 'upload_issue'


# DocumentVerification
class DocumentVerification(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, null=False, blank=False, default=DocumentVerificationStatus.created)

    # Relationships
    personal = models.ForeignKey(Personal, on_delete=models.DO_NOTHING,
                                 blank=True, null=True, related_name=Personal.rel_document_verifications)

    corporate = models.ForeignKey(Corporate, on_delete=models.DO_NOTHING,
                                  blank=True, null=True, related_name=Corporate.rel_document_verifications)

    passport = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                    blank=False, null=False, related_name=Document.rel_passport_verification)

    utilitybills = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                        blank=False, null=False, related_name=Document.rel_utilitybills_verification)

    selfie = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                  blank=False, null=False, related_name=Document.rel_selfie_verification)

    comment = models.TextField(null=True, blank=True)

    meta = JSONField(default=dict)  # This field type is a guess.
    is_identity_verified = models.BooleanField(default=False, verbose_name='Verified')
    is_identity_declined = models.BooleanField(default=False, verbose_name='Declined')
    is_applicant_changed = models.BooleanField(default=False)

    onfido_check_id = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_status = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_result = models.CharField(max_length=200, null=True, blank=True)
    onfido_check_created = models.DateTimeField(null=True, blank=True)
    verification_started_at = models.DateTimeField(null=True, blank=True)
    verification_attempts = models.IntegerField(default=0)

    # Relationships
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=False, null=False, related_name=Account.rel_documentverification)


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
    rel_licenseaddress = 'licenseaddress'

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
    kyc_account_approved    = 'kyc_account_approved'
    kyc_account_rejected    = 'kyc_account_rejected'


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
        NotificationType.kyc_account_approved: 'kyc_01',
        NotificationType.kyc_account_rejected: 'kyc_02',
    }

    notification_subjects = {
        'account_01_01': 'Password change request',
        'account_01_02': 'Your password was updated',
        'registration_01': 'Verify your email address',
        'registration_02': 'Accessing your jCash',
        'kyc_01': 'Completing Your KYC',
        'kyc_02': 'Completing Your KYC',
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
    min_limit = models.FloatField(null=False, default=0.0)
    max_limit = models.FloatField(null=False, default=999999999.0)

    rel_base_currencies = 'base_currencies'
    rel_reciprocal_currencies = 'reciprocal_currencies'
    rel_currencies = 'incoming_transactions'
    rel_exchanges = 'exchanges'
    rel_refunds = 'refunds'
    rel_licenseusers = 'licenseusers'

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


# Replenisher
class Replenisher(models.Model):
    transaction_id = models.CharField(max_length=120, null=False, blank=False, unique=True)
    type = models.CharField(max_length=40, null=False, blank=True, default='')
    mined_at = models.DateTimeField(null=True, blank=True)
    block_height = models.IntegerField(blank=True, null=True, unique=True)
    address = models.CharField(max_length=120, null=True, blank=True)
    is_removed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'replenisher'


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
    base_amount_actual = models.FloatField(default=0.0)
    reciprocal_amount = models.FloatField()
    reciprocal_amount_actual = models.FloatField(default=0.0)

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


# LicenseUserStatus
class LicenseAddressStatus:
    created = 'created'
    pending = 'pending'
    fail = 'fail'
    success = 'success'


# LicenseUser
class LicenseAddress(models.Model):
    status = models.CharField(max_length=20, default=LicenseAddressStatus.created)
    meta = JSONField(default=dict)
    is_remove_license = models.BooleanField(default=False)
    created_at = models.DateTimeField(null=True, auto_now_add=True)

    # Relationships
    address = models.ForeignKey(Address,
                                on_delete=models.DO_NOTHING,
                                related_name=Address.rel_licenseaddress)
    currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING,
                                 related_name=Currency.rel_licenseusers)

    class Meta:
        db_table = 'license_address'

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
    application = models.ForeignKey(Application, models.DO_NOTHING,
                                    related_name=Application.rel_incoming_txs, null=True)
    currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING,
                                 related_name=Currency.rel_currencies, null=True)
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
    currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING,
                                 related_name=Currency.rel_exchanges, null=True)
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
    currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING,
                                 related_name=Currency.rel_refunds, null=True)
    to_address = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField()
    mined_at = models.DateTimeField(null=True, blank=True)
    block_height = models.IntegerField(blank=True, null=True)
    value = models.FloatField(default=0)
    status = models.CharField(max_length=20, default=TransactionStatus.not_confirmed)
    meta = JSONField(default=dict)
    is_admin_approved = models.BooleanField(default=False)

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
