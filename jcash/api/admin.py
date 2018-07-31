import logging
from wsgiref.util import FileWrapper

from django.contrib import admin
from django.utils.html import format_html
from django.shortcuts import redirect, get_object_or_404, render
from django.utils.crypto import get_random_string
from django.conf.urls import url
from django.contrib import messages
from django.utils.safestring import mark_safe
from django.http import HttpResponse
from django.contrib.admin import SimpleListFilter
from django.contrib.admin.models import LogEntry, ADDITION, CHANGE, DELETION
from django.utils import timezone
from rest_framework.authtoken.models import Token
from allauth.account.models import EmailAddress
from django.urls import reverse

from jcash.api.models import (
    Address,
    AddressVerify,
    Account,
    Document,
    Currency,
    CurrencyPair,
    CurrencyPairRate,
    Application,
    IncomingTransaction,
    Exchange,
    Refund,
    Notification,
    Country,
    Personal,
    Corporate,
    Replenisher,
    DocumentVerification,
    AccountType,
    LicenseAddress,
)

from jcash.api import serializers
from jcash.api import utils
from jcash.commonutils import ga_integration


logger = logging.getLogger(__name__)

# Globally disable delete selected
admin.site.disable_action('delete_selected')


class FioFilledListFilter(SimpleListFilter):
    # Human-readable title which will be displayed in the
    # right admin sidebar just above the filter options.
    title = 'Form filled'

    # Parameter for the filter that will be used in the URL query.
    parameter_name = 'filled'

    def lookups(self, request, model_admin):
        """
        Returns a list of tuples. The first element in each
        tuple is the coded value for the option that will
        appear in the URL query. The second element is the
        human-readable name for the option that will appear
        in the right sidebar.
        """
        return (
            ('true', 'Filled'),
            ('false', 'Not Filled'),
        )

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        # Compare the requested value (either '80s' or '90s')
        # to decide how to filter the queryset.
        if self.value() == 'true':
            return queryset.exclude(first_name='',
                                    last_name='')
        elif self.value() == 'false':
            return queryset.filter(first_name='',
                                   last_name='')
        else:
            return queryset


class ReadonlyMixin:
    """
    Readonly view for non-superusers
    """

    def get_readonly_fields(self, request, obj=None):
        if request.user.is_superuser is False:
            fields = [f.name for f in self.model._meta.fields]
            return fields
        return self.readonly_fields

    def save_model(self, request, obj, form, change):
        if request.user.is_superuser is False:
            self.message_user(request, "Saving not allowed")
            return False
        else:
            super().save_model(request, obj, form, change)


@admin.register(Account)
class AccountAdmin(ReadonlyMixin, admin.ModelAdmin):
    list_display = ['id', 'username', 'customer_link', 'verification_link', 'verification_status',
                    'is_identity_verified', 'is_identity_declined', 'is_blocked', 'account_actions']
    list_filter = ['is_identity_verified', 'is_identity_declined', 'is_blocked']
    exclude = ['first_name', 'last_name', 'fullname', 'citizenship', 'birthday', 'residency',
               'country', 'street', 'town', 'postcode', 'terms_confirmed']
    search_fields = ['user__username']
    ordering = ('-id',)

    class Media:
        js = ['api/account.js',]

    def changelist_view(self, request, extra_context=None):
        self.request = request
        return super(AccountAdmin, self).changelist_view(request, extra_context=extra_context)

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [

            url(
                r'^(?P<account_id>.+)/action/$',
                self.admin_site.admin_view(self.account_action),
                name='account-action',
            ),
        ]
        return custom_urls + urls

    @staticmethod
    def username(obj):
        return obj.user.username

    def customer_link(self, obj):
        if hasattr(obj.user, 'account'):
            if hasattr(obj.user.account, Account.rel_personal):
                personal = obj.user.account.personal
                url = reverse('admin:api_personal_change', args=(personal.pk,))
                return format_html('<a href="{url}">{type}</a>', url=url, type=AccountType.personal)
            elif hasattr(obj.user.account, Account.rel_corporate):
                corporate = obj.user.account.corporate
                url = reverse('admin:api_corporate_change', args=(corporate.pk,))
                return format_html('<a href="{url}">{type}</a>', url=url, type=AccountType.corporate)
            else:
                return ''
        else:
            return ''
        customer_link.allow_tags = True

    def verification_link(self, obj):
        if hasattr(obj.user, Account.rel_documentverification):
            doc_verification = obj.user.documentverification.latest('created_at')
            url = reverse('admin:api_documentverification_change', args=(doc_verification.pk,))
            return format_html('<a href="{url}">{created_at}</a>',
                               url=url,
                               created_at=doc_verification.created_at)
        else:
            return ''
    verification_link.allow_tags = True

    def verification_status(self, obj):
        if hasattr(obj.user, Account.rel_documentverification):
            doc_verification = obj.user.documentverification.latest('created_at')
            return doc_verification.status
        else:
            return ''

    def account_actions(self, obj):
        return format_html(
            '<a class="button account-action" href="javascript:void(0)" data-url="{url}?action=block" data-action="block">Block</a>&nbsp;'
            '<a class="button account-action" href="javascript:void(0)" data-url="{url}?action=unblock" data-action="block">Unblock</a>&nbsp;'
            '<a class="button account-action" href="javascript:void(0)" data-url="{url}?action=approve" data-action="approve">Approve</a>&nbsp;'
            '<a class="button account-action" href="javascript:void(0)" data-url="{url}?action=decline" data-action="decline">Decline</a>&nbsp;',
            url = reverse('admin:account-action', args=[obj.pk]))

    account_actions.short_description = 'Account Actions'
    account_actions.allow_tags = True

    def block_account(self, request, account_id, *args, **kwargs):
        account = get_object_or_404(Account, pk=account_id)
        account.block_account()
        logger.info('Manual block for %s', account.user.username)
        messages.success(request,
                         mark_safe('Account <b>Blocked</b> for {}'.format(account.user.username)),
                         extra_tags='safe')
        return HttpResponse('OK')

    def unblock_account(self, request, account_id, *args, **kwargs):
        account = get_object_or_404(Account, pk=account_id)
        account.unblock_account()
        logger.info('Manual unblock for %s', account.user.username)
        messages.success(request,
                         mark_safe('Account <b>Unblocked</b> for {}'.format(account.user.username)),
                         extra_tags='safe')
        return HttpResponse('OK')

    def approve_identity_verification(self, request, account_id, *args, **kwargs):
        account = get_object_or_404(Account, pk=account_id)
        account.approve_verification()
        logger.info('Manual Identity approve for %s', account.user.username)
        ga_integration.on_status_verified_manual(account)
        messages.success(request,
                         mark_safe('Verification Status <b>Approved</b> for {}'.format(account.user.username)),
                         extra_tags='safe')
        return HttpResponse('OK')

    def decline_identity_verification(self, request, account_id, *args, **kwargs):
        reason = request.POST.get('reason')
        account = get_object_or_404(Account, pk=account_id)
        logger.info('Manual Identity decline for %s', account.user.username)
        account.decline_verification(reason)
        ga_integration.on_status_not_verified_manual(account)
        messages.success(request,
                         mark_safe('Verification Status <b>Declined</b> for {}'.format(account.user.username)),
                         extra_tags='safe')
        return HttpResponse('OK')

    def account_action(self, request, account_id, *args, **kwargs):
        if request.method == 'POST' and request.POST.get('confirm'):
            action = request.POST.get('action')
            if action == 'block':
                return self.block_account(request, account_id)
            elif action == 'unblock':
                return self.unblock_account(request, account_id)
            elif action == 'approve':
                return self.approve_identity_verification(request, account_id)
            elif action == 'decline':
                return self.decline_identity_verification(request, account_id)
        else:
            account = get_object_or_404(Account, pk=account_id)
            action = request.GET.get('action')
            return render(request, 'account_action_confirm.html', {'action': action, 'account': account, 'opts': account._meta})


@admin.register(Address)
class AddressAdmin(ReadonlyMixin, admin.ModelAdmin):
    list_display = ['id', 'created_at', 'username', 'address', 'type',
                    'is_verified', 'is_removed', 'is_rejected']
    list_filter = ['is_verified', 'is_removed', 'is_rejected']
    search_fields = ['user__username', 'address']
    ordering = ('-created_at',)

    @staticmethod
    def username(obj):
        return obj.user.username


@admin.register(AddressVerify)
class AddressVerifyAdmin(ReadonlyMixin, admin.ModelAdmin):
    list_display = ['id', 'created_at', 'username', 'address', 'is_verified', 'message',]
    list_filter = ['is_verified']
    search_fields = ['id', 'address__user__username', 'address__address']
    ordering = ('-created_at',)

    @staticmethod
    def username(obj):
        return obj.address.user.username

    @staticmethod
    def address(obj):
        return obj.address.address


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['user', 'image']
    search_fields = ['user__username']


@admin.register(Currency)
class CurrencyAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'display_name', 'symbol', 'exchanger_address',
                    'view_address', 'controller_address', 'is_erc20_token', 'round_digits',
                    'min_limit', 'max_limit', 'balance']
    search_fields = ['id', 'display_name', 'symbol', 'exchanger_address',
                     'view_address', 'controller_address']
    ordering = ('-created_at',)


@admin.register(CurrencyPair)
class CurrencyPairAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'display_name', 'symbol', 'base_cur','rec_cur',
                    'is_exchangeable', 'is_buyable', 'is_sellable', 'buy_fee_percent',
                    'sell_fee_percent']
    search_fields = ['id', 'display_name', 'symbol']
    raw_id_fields = ('base_currency', 'reciprocal_currency')
    ordering = ('-id',)

    @staticmethod
    def base_cur(obj):
        return obj.base_currency.symbol

    @staticmethod
    def rec_cur(obj):
        return obj.reciprocal_currency.symbol


@admin.register(CurrencyPairRate)
class CurrencyPairRateAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'currency_name', 'buy_price', 'sell_price']
    search_fields = ['id', 'currency_pair__symbol', 'currency_pair__display_name']
    raw_id_fields = ('currency_pair',)
    ordering = ('-created_at',)

    @staticmethod
    def currency_name(obj):
        return obj.currency_pair.display_name


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'username', 'address', 'currency_name', 'currency_rate',
                    'base_currency', 'reciprocal_currency', 'rate', 'base_amount', 'reciprocal_amount', 'status']
    ordering = ('-created_at',)

    @staticmethod
    def username(obj):
        return obj.address.user.username

    @staticmethod
    def currency_name(obj):
        return obj.currency_pair.display_name

    @staticmethod
    def currency_rate(obj):
        return obj.currency_pair_rate.pk


@admin.register(IncomingTransaction)
class IncomingTransactionAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'transaction_id', 'username', 'application', 'from_address',
                    'to_address', 'symbol', 'value', 'mined_at', 'block_height', 'status']
    search_fields = ['id', 'application__user__username', 'to_address', 'from_address', 'transaction_id',
                     'block_height', 'value', 'currency__display_name', 'status']
    ordering = ('-mined_at',)

    @staticmethod
    def username(obj):
        if obj.application is not None:
            return obj.application.user.username
        return '-'

    @staticmethod
    def symbol(obj):
        if obj.currency is not None:
            return obj.currency.display_name
        return '-'


@admin.register(Exchange)
class ExchangeAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'transaction_id', 'username', 'application', 'to_address', 'symbol',
                    'value', 'status']
    search_fields = ['id', 'application__user__username', 'to_address', 'value', 'transaction_id',
                     'currency__display_name', 'status']
    ordering = ('-created_at',)

    @staticmethod
    def username(obj):
        if obj.application is not None:
            return obj.application.user.username
        return '-'

    @staticmethod
    def symbol(obj):
        if obj.currency is not None:
            return obj.currency.display_name
        return '-'


@admin.register(Refund)
class RefundAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'transaction_id', 'username', 'application', 'to_address', 'symbol',
                    'value', 'status']
    search_fields = ['id', 'application__user__username', 'to_address', 'value', 'transaction_id',
                     'currency__display_name', 'status']
    ordering = ('-created_at',)

    @staticmethod
    def username(obj):
        if obj.application is not None:
            return obj.application.user.username
        return '-'

    @staticmethod
    def symbol(obj):
        if obj.currency is not None:
            return obj.currency.display_name
        return '-'


@admin.register(LicenseAddress)
class LicenseAddressAdmin(admin.ModelAdmin):
    list_display = ['id', 'user_name', 'address', 'currency_name',
                    'created_at', 'status', 'is_remove_license']
    search_fields = ['user__username', 'address__address', 'currency__display_name', 'status']
    ordering = ('-created_at',)

    @staticmethod
    def user_name(obj):
        if obj.address is not None and obj.address.user is not None:
            return obj.address.user.username
        return '-'

    @staticmethod
    def address(obj):
        if obj.address is not None:
            return obj.address.address
        return '-'

    @staticmethod
    def currency_name(obj):
        if obj.currency is not None:
            return obj.currency.display_name
        return '-'


@admin.register(Country)
class CountryAdmin(admin.ModelAdmin):
    list_display = ['id', 'type', 'name', 'is_removed']
    search_fields = ['id', 'type', 'name']
    list_filter = ['is_removed']


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'created', 'type', 'email', 'is_sended', 'sended']


@admin.register(Personal)
class PersonalAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'fullname', 'nationality', 'birthday', 'phone', 'email',
                    'country', 'street', 'apartment', 'city', 'postcode',
                    'profession', 'income_source', 'assets_origin', 'jcash_use', 'created_at']


@admin.register(Corporate)
class CorporateAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'name', 'domicile_country', 'business_phone', 'business_email', 'country',
                    'street', 'apartment', 'city', 'postcode', 'industry', 'assets_origin',
                    'currency_nature', 'assets_origin_description', 'jcash_use',
                    'contact_fullname', 'contact_birthday', 'contact_nationality', 'contact_residency',
                    'contact_phone', 'contact_email', 'contact_street', 'contact_apartment',
                    'contact_city', 'contact_postcode', 'created_at']


@admin.register(Replenisher)
class ReplenisherAdmin(admin.ModelAdmin):
    list_display = ['id', 'address', 'is_removed', 'created_at', 'last_updated_at']
    search_fields = ['address']
    list_filter = ['is_removed']
    ordering = ('id',)


@admin.register(DocumentVerification)
class DocumentVerificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'created_at', 'status',
                    'passport_thumb', 'passport_status',
                    'utilitybills_thumb', 'utilitybills_status',
                    'selfie_thumb', 'selfie_status']
    search_fields = ['id']
    ordering = ('-id',)

    @staticmethod
    def username(obj):
        return obj.user.username

    def passport_status(self, obj):
        if obj.passport:
            return obj.passport.onfido_check_result
        else:
            return None

    def utilitybills_status(self, obj):
        if obj.utilitybills:
            return obj.utilitybills.onfido_check_result
        else:
            return None

    def selfie_status(self, obj):
        if obj.selfie:
            return obj.selfie.onfido_check_result
        else:
            return None

    def document_thumb(self, obj):
        if not obj.image:
            return ''
        if obj.ext.lower() in ('jpg', 'jpeg', 'png'):
            return format_html('<a href="{src}"><img src="{src}" height="30"/></a>', src=obj.image.url)
        else:
            return obj.image.url

    def passport_thumb(self, obj):
        return self.document_thumb(obj.passport)

    def utilitybills_thumb(self, obj):
        return self.document_thumb(obj.utilitybills)

    def selfie_thumb(self, obj):
        return self.document_thumb(obj.selfie)

    passport_thumb.short_description = 'Passport'
    passport_thumb.allow_tags = True
    utilitybills_thumb.short_description = 'Utilitybills'
    utilitybills_thumb.allow_tags = True
    selfie_thumb.short_description = 'Selfie'
    selfie_thumb.allow_tags = True


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ['id', 'action_time', 'username', 'object_id', 'object_repr', 'actionflag', 'change_message']
    search_fields = ['user__username', 'actionflag', 'object_repr']
    ordering = ('-action_time','-id')

    @staticmethod
    def username(obj):
        return obj.user.username

    def actionflag(self, obj):
        if obj.action_flag == CHANGE:
            return 'CHANGE'
        elif obj.action_flag == ADDITION:
            return 'ADDITION'
        elif obj.action_flag == DELETION:
            return 'DELETION'
        else:
            return str(obj.action_flag)


admin.site.unregister(EmailAddress)


@admin.register(EmailAddress)
class EmailAddress(ReadonlyMixin, admin.ModelAdmin):
    list_display = ['user', 'email', 'verified']
    search_fields = ['email']

    actions = ['verify']

    def verify(self, request, queryset):
        emails = queryset.all()
        for email in emails:
            logger.info('Manual email varification %s', email.email)
            email.verified = True
            email.save()
        op_names = ', '.join([em.email for em in emails])
        self.message_user(request, "Emails {} was marked as verified".format(op_names))
