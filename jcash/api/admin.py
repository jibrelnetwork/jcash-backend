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
from django.utils import timezone


from rest_framework.authtoken.models import Token
from allauth.account.models import EmailAddress

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
    Corporate
)

from jcash.api import serializers
from jcash.api import utils
#from jcash.commonutils import ga_integration


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
class AccountAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'first_name', 'last_name',
                    'is_identity_verified', 'is_identity_declined',
                    'is_blocked', 'comment']
    list_filter = ['is_identity_verified', 'is_identity_declined', 'is_blocked']
    search_fields = ['user__username']
    ordering = ('-id',)

    @staticmethod
    def username(obj):
        return obj.user.username


@admin.register(Address)
class AddressAdmin(ReadonlyMixin, admin.ModelAdmin):
    list_display = ['id', 'created_at', 'username', 'address', 'type',
                    'is_verified', 'is_allowed', 'is_removed', 'is_rejected']
    list_filter = ['is_verified', 'is_allowed', 'is_removed', 'is_rejected']
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
                    'min_limit', 'max_limit', 'balance', 'abi']
    search_fields = ['id', 'display_name', 'symbol', 'exchanger_address',
                     'view_address', 'controller_address']
    ordering = ('-created_at',)


@admin.register(CurrencyPair)
class CurrencyPairAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'display_name', 'symbol', 'base_cur','rec_cur',
                    'is_exchangeable', 'is_buyable', 'is_sellable']
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
                    'profession', 'income_source', 'asstets_origin', 'jcash_use', 'created_at']


@admin.register(Corporate)
class CorporateAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'name', 'domicile_country', 'business_phone', 'business_email', 'country',
                    'street', 'apartment', 'city', 'postcode', 'industry', 'asstets_origin',
                    'currency_nature', 'asstets_origin_description', 'jcash_use',
                    'contact_fullname', 'contact_birthday', 'contact_nationality', 'contact_residency',
                    'contact_phone', 'contact_email', 'contact_street', 'contact_apartment',
                    'contact_city', 'contact_postcode', 'created_at']


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
