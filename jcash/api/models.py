import logging
import uuid

from allauth.account.models import EmailAddress
from django.db import models, transaction
from django.conf import settings
from django.contrib.postgres.fields import JSONField
from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _
from concurrency.fields import IntegerVersionField

from jcash.commonutils import notify
from jcash.settings import FRONTEND_URL, LOGIC__VIDEO_VERIFY_TEXT


logger = logging.getLogger(__name__)


# ObjStatus
class ObjStatus:
    def __init__(self, name, description, hide=False):
        self.name = name
        self.description = description
        self.hide = hide

    def __repr__(self):
        return self.name

    def __str__(self):
        if not isinstance(self.name, str):
            raise Exception(_('Value is not str.'))
        return self.name

    def __int__(self):
        if not isinstance(self.name, int):
            raise Exception(_('Value is not int.'))
        return self.name


# Account statuses
class AccountStatus:
    blocked = ObjStatus('blocked', 'blocked account')
    pending = ObjStatus('pending', 'user''s documents in pending mode')
    verified = ObjStatus('verified', 'verified account')
    declined = ObjStatus('declined', 'declined account')
    email_confirmation = ObjStatus('email_confirmation', 'email confirmation required')
    created = ObjStatus('created', 'new account')
    needs_video_verification = ObjStatus('needs-video-verification', 'needs video verification')
    pending_approve_video_verification = ObjStatus('pending-approve-video-verification',
                                                   'user''s video verification in pending mode')


# Account types
class AccountType:
    personal = 'personal'
    corporate = 'corporate'
    beneficiary = 'beneficiary'


def get_account_types():
    """
    Get account types of the service
    """
    return [getattr(AccountType, attr) for attr in dir(AccountType) \
            if not callable(getattr(AccountType, attr)) and not attr.startswith("__") and \
            (not hasattr(getattr(AccountType, attr), 'hide') or \
             not getattr(AccountType, attr).hide)]


# Account model
class Account(models.Model):
    version = IntegerVersionField()
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
        indexes = (
            models.Index(fields=['type']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_updated_at']),
            models.Index(fields=['is_identity_verified']),
            models.Index(fields=['is_identity_declined']),
            models.Index(fields=['is_blocked']),
        )

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

            notify.send_email_jcash_application_approved(self.user.email if self.user else None,
                                                         FRONTEND_URL,
                                                         self.user.id if self.user else None)

    def decline_verification(self, reason):
        with transaction.atomic():
            self.is_identity_verified = False
            self.is_identity_declined = True
            self.save()
            doc_verification = None
            customer = self.get_customer()
            if customer:
                customer.status = str(CustomerStatus.declined)
                customer.kyc_step = int(KycSteps.declined)
                customer.save()
                if hasattr(customer, 'document_verifications') and \
                        customer.document_verifications.count() > 0:

                    doc_verification = customer.document_verifications.latest('created_at')
            if doc_verification:
                doc_verification.is_identity_verified = False
                doc_verification.is_identity_declined = True
                doc_verification.comment = reason
                doc_verification.save()

            notify.send_email_jcash_application_unsuccessful(self.user.email if self.user else None,
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
    def get_status(cls, obj):
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

    class Meta:
        indexes = (
            models.Index(fields=['type']),
            models.Index(fields=['is_removed']),
        )


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
    confirmations = ObjStatus('confirmations', 'confirmations required (personal, corporate)')
    contact_info = ObjStatus('contact_info', 'contact info required (personal')
    company_info = ObjStatus('company_info', 'company info required (corporate')
    address = ObjStatus('address', 'address info required (personal)')
    business_address = ObjStatus('business_address', 'business address info required (corporate)')
    income_info = ObjStatus('income_info', 'income info required (personal, corporate)')
    primary_contact = ObjStatus('primary_contact', 'primary contact info required (corporate)')
    documents = ObjStatus('documents', 'documents required (personal, corporate)')
    video_verification = ObjStatus('video_verification', 'video verification required (personal, corporate)')
    submitted = ObjStatus('submitted', 'all fields submitted (personal, corporate)')
    declined = ObjStatus('declined', 'customer declined (personal, corporate)')


# KYC steps
class KycSteps:
    declined = ObjStatus(-1, 'customer declined (personal, corporate)')
    submitted = ObjStatus(0, 'all fields submitted (personal, corporate)')
    confirmations = ObjStatus(1, 'confirmations required (personal, corporate)')
    contact_info = ObjStatus(2, 'contact info required (personal')
    company_info = ObjStatus(2, 'company info required (corporate')
    address = ObjStatus(3, 'personal address/business address required (personal, corporate)')
    income_info = ObjStatus(4, 'income info required (personal, corporate)')
    primary_contact = ObjStatus(5, 'primary contact info required (corporate)')
    documents = ObjStatus(6, 'documents required (personal, corporate)')
    video_verification = ObjStatus(7, 'video verification required (personal, corporate)')


class DocumentGroup:
    personal = 'personal'
    corporate = 'corporate'


class DocumentType:
    passport = 'passport'
    utilitybills = 'utilitybills'
    selfie = 'selfie'
    report = 'report'
    video = 'video'


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
    version = IntegerVersionField()
    image = models.FileField('uploaded document', upload_to=DocumentHelper.unique_document_filename)  # stores the uploaded documents
    ext = models.CharField(max_length=20, null=False, blank=True)
    type = models.CharField(max_length=20, null=False, blank=True)
    group = models.CharField(max_length=20, null=False, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Relationships
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=False, null=False, related_name=Account.rel_documents)

    onfido_document_id = models.CharField(max_length=200, null=True, blank=True)

    rel_passport_verification = 'passport_verification'
    rel_utilitybills_verification = 'utilitybills_verification'
    rel_selfie_verification = 'selfie_verification'
    rel_report_verification = 'report_verification'
    rel_video_verification = 'video_verification'
    rel_personal_passport = 'personal_passport'
    rel_personal_utilitybills = 'personal_utilitybills'
    rel_personal_selfie = 'personal_selfie'
    rel_personal_video = 'personal_video'
    rel_corporate_passport = 'corporate_passport'
    rel_corporate_utilitybills = 'corporate_utilitybills'
    rel_corporate_selfie = 'corporate_selfie'
    rel_corporate_video = 'corporate_video'

    class Meta:
        db_table = 'document'
        indexes = (
            models.Index(fields=['ext']),
            models.Index(fields=['type']),
            models.Index(fields=['group']),
            models.Index(fields=['created_at']),
        )


class Personal(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = IntegerVersionField()

    # Confirmations
    is_terms_agreed = models.BooleanField(default=False)
    is_not_political = models.BooleanField(default=False)
    is_ultimate_owner = models.BooleanField(default=False)
    is_information_confirmed = models.BooleanField(default=False)

    # Contact information
    firstname = models.CharField(max_length=PersonalFieldLength.fullname, null=False, blank=True)
    lastname = models.CharField(max_length=PersonalFieldLength.fullname, null=False, blank=True)
    middlename = models.CharField(max_length=PersonalFieldLength.fullname, null=True, blank=True)
    nationality = models.CharField(max_length=PersonalFieldLength.nationality, null=False, blank=True)
    birthday = models.DateField(null=True, blank=True)
    phone = models.CharField(max_length=PersonalFieldLength.phone, null=False, blank=True)

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

    # Documents
    passport = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                    blank=True, null=True, related_name=Document.rel_personal_passport)
    utilitybills = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                        blank=True, null=True, related_name=Document.rel_personal_utilitybills)
    selfie = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                  blank=True, null=True, related_name=Document.rel_personal_selfie)
    video = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                    blank=True, null=True, related_name=Document.rel_personal_video)

    # Modifications time
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=True)

    status = models.CharField(max_length=20, default='')
    kyc_step = models.IntegerField(default=-2)
    onfido_applicant_id = models.CharField(max_length=200, null=True, blank=True)

    # Relationships
    account = models.OneToOneField(Account, on_delete=models.DO_NOTHING,
                                   null=True, related_name=Account.rel_personal)

    rel_documents = 'documents'
    rel_document_verifications = 'document_verifications'

    class Meta:
        indexes = (
            models.Index(fields=['country']),
            models.Index(fields=['city']),
            models.Index(fields=['profession']),
            models.Index(fields=['jcash_use']),
            models.Index(fields=['income_source']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_updated_at']),
            models.Index(fields=['status']),
            models.Index(fields=['onfido_applicant_id']),
        )


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
    version = IntegerVersionField()

    # Confirmations
    is_terms_agreed = models.BooleanField(default=False)
    is_not_political = models.BooleanField(default=False)
    is_ultimate_owner = models.BooleanField(default=False)
    is_information_confirmed = models.BooleanField(default=False)

    # Company information
    name = models.CharField(max_length=CorporateFieldLength.name,
                            null=False, blank=True)
    domicile_country = models.CharField(max_length=CorporateFieldLength.country,
                                        null=False, blank=True)
    business_phone = models.CharField(max_length=CorporateFieldLength.phone,
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
    contact_firstname = models.CharField(max_length=CorporateFieldLength.fullname, null=False, blank=True)
    contact_lastname = models.CharField(max_length=CorporateFieldLength.fullname, null=False, blank=True)
    contact_middlename = models.CharField(max_length=CorporateFieldLength.fullname, null=True, blank=True)

    contact_birthday = models.DateField(null=True, blank=True)
    contact_nationality = models.CharField(max_length=CorporateFieldLength.country, null=False, blank=True)
    contact_residency = models.CharField(max_length=CorporateFieldLength.country, null=False, blank=True)
    contact_phone = models.CharField(max_length=CorporateFieldLength.phone, null=False, blank=True)
    contact_email = models.CharField(max_length=CorporateFieldLength.email, null=False, blank=True)
    contact_street = models.CharField(max_length=CorporateFieldLength.street, null=False, blank=True)
    contact_apartment = models.CharField(max_length=CorporateFieldLength.apartment, null=False, blank=True)
    contact_city = models.CharField(max_length=CorporateFieldLength.city, null=False, blank=True)
    contact_postcode = models.CharField(max_length=CorporateFieldLength.postcode, null=False, blank=True)

    # Documents
    passport = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                    blank=True, null=True, related_name=Document.rel_corporate_passport,)
    utilitybills = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                        blank=True, null=True, related_name=Document.rel_corporate_utilitybills)
    selfie = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                  blank=True, null=True, related_name=Document.rel_corporate_selfie)
    video = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                    blank=True, null=True, related_name=Document.rel_corporate_video)

    # Modifications time
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated_at = models.DateTimeField(auto_now_add=True)

    status = models.CharField(max_length=20, default='')
    kyc_step = models.IntegerField(default=-2)
    onfido_applicant_id = models.CharField(max_length=200, null=True, blank=True)

    # Relationships
    account = models.OneToOneField(Account, on_delete=models.DO_NOTHING,
                                   null=True, related_name=Account.rel_corporate)

    rel_documents = 'documents'
    rel_document_verifications = 'document_verifications'

    class Meta:
        indexes = (
            models.Index(fields=['country']),
            models.Index(fields=['city']),
            models.Index(fields=['industry']),
            models.Index(fields=['jcash_use']),
            models.Index(fields=['name']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_updated_at']),
            models.Index(fields=['status']),
            models.Index(fields=['onfido_applicant_id']),
        )


class DocumentVerificationStatus:
    created = 'created'
    submitted = 'submitted'
    upload_issue = 'upload_issue'


# DocumentVerification
class DocumentVerification(models.Model):
    version = IntegerVersionField()
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

    video = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                    blank=True, null=True, related_name=Document.rel_video_verification)

    report = models.OneToOneField(Document, on_delete=models.DO_NOTHING,
                                  blank=True, null=True, related_name=Document.rel_report_verification)

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

    video_message = models.CharField(unique=False, max_length=1024, default='')
    video_reg_id = models.CharField(unique=False, null=True, blank=True, max_length=1024)

    # Relationships
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING,
                             blank=False, null=False, related_name=Account.rel_documentverification)

    class Meta:
        indexes = (
            models.Index(fields=['created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['is_identity_verified']),
            models.Index(fields=['is_identity_declined']),
            models.Index(fields=['is_applicant_changed']),
            models.Index(fields=['onfido_check_id']),
            models.Index(fields=['onfido_check_status']),
            models.Index(fields=['onfido_check_result']),
            models.Index(fields=['onfido_check_created']),
            models.Index(fields=['verification_started_at']),
            models.Index(fields=['verification_attempts']),
        )


# Address model
class Address(models.Model):
    version = IntegerVersionField()
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
                             blank=True, null=True, related_name=Account.rel_addresses)

    class Meta:
        db_table = 'address'
        indexes = (
            models.Index(fields=['address']),
            models.Index(fields=['type']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['is_rejected']),
            models.Index(fields=['is_removed']),
            models.Index(fields=['is_allowed']),
            models.Index(fields=['created_at']),
        )

    def __str__(self):
        return '{}: {}'.format(self.type, self.address)


# AddressMessage
class AddressVerify(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = IntegerVersionField()
    sig = models.CharField(unique=True, max_length=255, null=True, blank=True)
    message = models.CharField(unique=False, max_length=1024)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    # Relationships
    address = models.ForeignKey(Address, on_delete=models.DO_NOTHING,
                                blank=False, null=False, related_name=Address.rel_verifies)

    class Meta:
        db_table = 'address_verify'
        indexes = (
            models.Index(fields=['created_at']),
            models.Index(fields=['is_verified']),
        )


class NotificationType:
    eth_address_added              = 'eth_address_added'
    eth_address_removed            = 'eth_address_removed'
    exchange_request               = 'exchange_request'
    exchange_successful            = 'exchange_successful'
    exchange_unsuccessful          = 'exchange_unsuccessful'
    few_steps_away                 = 'few_steps_away'
    jcash_application_approved     = 'jcash_application_approved'
    jcash_application_underway     = 'jcash_application_underway'
    jcash_application_unsuccessful = 'jcash_application_unsuccessful'
    new_login_detected             = 'new_login_detected'
    password_reset_confirmation    = 'password_reset_confirmation'
    password_reset                 = 'password_reset'
    refund_successful              = 'refund_successful'
    verify_email                   = 'verify_email'
    video_verification             = 'video_verification'


def get_email_templates():
    """
    Get email templates of the service
    """
    return [getattr(NotificationType, attr) for attr in dir(NotificationType) \
            if not callable(getattr(NotificationType, attr)) and not attr.startswith("__") and \
            (not hasattr(getattr(NotificationType, attr), 'hide') or \
             not getattr(NotificationType, attr).hide)]


class Notification(models.Model):
    version = IntegerVersionField()
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
        indexes = (
            models.Index(fields=['type']),
            models.Index(fields=['email']),
            models.Index(fields=['created']),
            models.Index(fields=['sended']),
            models.Index(fields=['is_sended']),
        )

    notification_keys = {
        NotificationType.eth_address_added: 'eth_address_added',
        NotificationType.eth_address_removed: 'eth_address_removed',
        NotificationType.exchange_request: 'exchange_request',
        NotificationType.exchange_successful: 'exchange_successful',
        NotificationType.exchange_unsuccessful: 'exchange_unsuccessful',
        NotificationType.few_steps_away: 'few_steps_away',
        NotificationType.jcash_application_approved: 'jcash_application_approved',
        NotificationType.jcash_application_underway: 'jcash_application_underway',
        NotificationType.jcash_application_unsuccessful: 'jcash_application_unsuccessful',
        NotificationType.new_login_detected: 'new_login_detected',
        NotificationType.password_reset_confirmation: 'password_reset_confirmation',
        NotificationType.password_reset: 'password_reset',
        NotificationType.refund_successful: 'refund_successful',
        NotificationType.verify_email: 'verify_email',
        NotificationType.video_verification: 'video_verification',
    }

    notification_subjects = {
        'eth_address_added': 'ETH address added',
        'eth_address_removed': 'ETH address removed',
        'exchange_request': 'Requested an exchange',
        'exchange_successful': 'Exchange successful',
        'exchange_unsuccessful': 'Uh oh...exchange unsuccessful',
        'few_steps_away': 'You\'re only a few steps away!',
        'jcash_application_approved': 'Approved!',
        'jcash_application_underway': 'Jcash application underway!',
        'jcash_application_unsuccessful': 'Uh oh...application unsuccessful',
        'new_login_detected': 'A new device was used to access your Jcash account',
        'password_reset_confirmation': 'Your password was reset!',
        'password_reset': 'Uh oh..forgot your password?',
        'refund_successful': 'Refund successful!',
        'verify_email': 'One Step away!',
        'video_verification': 'Needs video verification!',
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
    version = IntegerVersionField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING)
    event = models.CharField(max_length=20)
    url = models.CharField(max_length=300, null=False)
    created = models.DateTimeField(auto_now_add=True)
    sended = models.DateTimeField(null=True)
    status = models.IntegerField(blank=True, null=True)
    meta = JSONField(default=dict)  # This field type is a guess.

    class Meta:
        db_table = 'affiliate'
        indexes = (
            models.Index(fields=['event']),
            models.Index(fields=['url']),
            models.Index(fields=['created']),
            models.Index(fields=['sended']),
            models.Index(fields=['status']),
        )


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
    balance = models.FloatField(default=0.0)
    total_supply = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    abi = JSONField(default=dict)
    round_digits = models.IntegerField(null=False, default=8)
    min_limit = models.FloatField(null=False, default=0.0)
    max_limit = models.FloatField(null=False, default=999999999.0)
    is_disabled = models.BooleanField(default=True)

    rel_base_currencies = 'base_currencies'
    rel_reciprocal_currencies = 'reciprocal_currencies'
    rel_incomingtxs = 'incoming_transactions'
    rel_exchanges = 'exchanges'
    rel_refunds = 'refunds'
    rel_licenseusers = 'licenseusers'

    class Meta:
        db_table = 'currency'
        indexes = (
            models.Index(fields=['display_name']),
            models.Index(fields=['symbol']),
            models.Index(fields=['exchanger_address']),
            models.Index(fields=['view_address']),
            models.Index(fields=['controller_address']),
            models.Index(fields=['license_registry_address']),
            models.Index(fields=['is_erc20_token']),
            models.Index(fields=['created_at']),
        )


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
    sort_id = models.IntegerField(null=False, default=0)

    rel_currency_pair_rates = 'currency_pair_rates'
    rel_applications = 'applications'

    class Meta:
        db_table = 'currency_pair'
        indexes = (
            models.Index(fields=['display_name']),
            models.Index(fields=['symbol']),
            models.Index(fields=['is_exchangeable']),
            models.Index(fields=['created_at']),
            models.Index(fields=['is_buyable']),
            models.Index(fields=['is_sellable']),
        )


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
        indexes = (
            models.Index(fields=['created_at']),
        )


# JntRate
class JntRate(models.Model):
    source = models.CharField(max_length=30)  # source of price information (e.g. BiBox, Gate.io)
    price = models.FloatField()
    created_at = models.DateTimeField()
    meta = JSONField(default={})

    class Meta:
        db_table = 'jnt_rate'
        indexes = (
            models.Index(fields=['created_at']),
            models.Index(fields=['source']),
        )


# LiquidityProvider
class LiquidityProvider(models.Model):
    entity = models.CharField(max_length=255)
    address = models.CharField(max_length=255, blank=True, null=True)
    jnt_pledge = models.FloatField(default=0.0)

    class Meta:
        db_table = 'liquidity_provider'
        indexes = (
            models.Index(fields=['entity']),
        )


# ProofOfSolvency
class ProofOfSolvency(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    meta = JSONField(default={})

    class Meta:
        db_table = 'proof_of_solvency'
        indexes = (
            models.Index(fields=['created_at']),
        )


# Replenisher
class Replenisher(models.Model):
    version = IntegerVersionField()
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
        indexes = (
            models.Index(fields=['type']),
            models.Index(fields=['mined_at']),
            models.Index(fields=['block_height']),
            models.Index(fields=['is_removed']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_updated_at']),
        )


# ApplicationStatus
class ApplicationStatus:
    created = ObjStatus('created', 'new application')
    cancelled = ObjStatus('cancelled', 'cancelled application')
    waiting = ObjStatus('waiting', 'waiting for user tx')
    confirming = ObjStatus('confirming', 'we received unexpected value (and CAN go further)')
    converting = ObjStatus('converting', 'we sent tx but it was not mined')
    converted = ObjStatus('converted', 'converted, tx is mined')
    refunding = ObjStatus('refunding', 'clicked "No, refund" (tx is in progress, not mined yet)')
    refunded = ObjStatus('refunded', 'refunded, tx is mined', True)


# ApplicationCancelReason
class ApplicationCancelReason:
    cancelled_by_user = ObjStatus('cancelled_by_user', 'Cancelled by user')
    cancelled_by_timeout = ObjStatus('cancelled_by_timeout', 'Cancelled by timeout')
    cancelled_by_contract = ObjStatus('cancelled_by_contract', 'Cancelled due to execution error')
    cancelled_by_currency_balance = ObjStatus('cancelled_by_currency_balance', 'Cancelled by currency limits')
    cancelled_by_currency_limits = ObjStatus('cancelled_by_currency_limits', 'Cancelled by currency limits')
    not_enough_jnt = ObjStatus('not_enough_jnt', 'Not enough JNT')


# Application
class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = IntegerVersionField()
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
    fee = models.FloatField(default=0.0)

    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_reverse = models.BooleanField(default=False)
    status = models.CharField(max_length=10, default=str(ApplicationStatus.created))
    reason = models.CharField(max_length=35, blank=True, default='')
    meta = JSONField(default=dict)

    rel_exchanges = 'exchanges'
    rel_refundes = 'refundes'
    rel_incoming_txs = 'incoming_txs'

    class Meta:
        db_table = 'application'
        indexes = (
            models.Index(fields=['exchanger_address']),
            models.Index(fields=['base_currency']),
            models.Index(fields=['reciprocal_currency']),
            models.Index(fields=['base_amount_actual']),
            models.Index(fields=['reciprocal_amount_actual']),
            models.Index(fields=['created_at']),
            models.Index(fields=['expired_at']),
            models.Index(fields=['is_active']),
            models.Index(fields=['is_reverse']),
            models.Index(fields=['status']),
        )


# LicenseUserStatus
class LicenseAddressStatus:
    created = 'created'
    pending = 'pending'
    fail = 'fail'
    success = 'success'


# LicenseUser
class LicenseAddress(models.Model):
    version = IntegerVersionField()
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
        indexes = (
            models.Index(fields=['status']),
            models.Index(fields=['is_remove_license']),
            models.Index(fields=['created_at']),
        )

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
    version = IntegerVersionField()
    transaction_id = models.CharField(max_length=120, null=False, blank=False, unique=True)
    application = models.ForeignKey(Application, models.DO_NOTHING,
                                    related_name=Application.rel_incoming_txs, null=True)
    currency = models.ForeignKey(Currency, on_delete=models.DO_NOTHING,
                                 related_name=Currency.rel_incomingtxs, null=True)
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
        indexes = (
            models.Index(fields=['transaction_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['mined_at']),
            models.Index(fields=['block_height']),
            models.Index(fields=['from_address']),
            models.Index(fields=['to_address']),
            models.Index(fields=['value']),
            models.Index(fields=['status']),
            models.Index(fields=['is_linked']),
        )


# Exchange Fee
class ExchangeFee(models.Model):
    value = models.FloatField(default=0)
    type = models.CharField(max_length=20, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    from_block = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'exchange_fee'


# Exchange
class Exchange(models.Model):
    version = IntegerVersionField()
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
        indexes = (
            models.Index(fields=['transaction_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['mined_at']),
            models.Index(fields=['block_height']),
            models.Index(fields=['to_address']),
            models.Index(fields=['value']),
            models.Index(fields=['status']),
        )


# Refund
class Refund(models.Model):
    version = IntegerVersionField()
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
        indexes = (
            models.Index(fields=['transaction_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['mined_at']),
            models.Index(fields=['block_height']),
            models.Index(fields=['to_address']),
            models.Index(fields=['value']),
            models.Index(fields=['status']),
            models.Index(fields=['is_admin_approved']),
        )
