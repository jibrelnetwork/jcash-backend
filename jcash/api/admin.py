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

    def username(self, obj):
        return obj.user.username


@admin.register(Address)
class AddressAdmin(ReadonlyMixin, admin.ModelAdmin):
    list_display = ['created_at', 'address', 'type', 'is_verified', 'is_rejected']
    search_fields = ['user__username', 'address']
    list_select_related = ('user__account',)


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['user', 'image']
    search_fields = ['user__username']


@admin.register(Currency)
class CurrencyAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'display_name', 'symbol', 'exchanger_address', 'view_address',
                    'controller_address','is_erc20_token','balance','abi']


@admin.register(CurrencyPair)
class CurrencyPairAdmin(admin.ModelAdmin):
    list_display = ['created_at', 'display_name', 'symbol', 'base_currency','reciprocal_currency',
                    'is_exchangeable', 'is_buyable', 'is_sellable']


@admin.register(CurrencyPairRate)
class CurrencyPairRateAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'currency_pair', 'buy_price', 'sell_price']


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['id','address','currency_pair','currency_pair_rate',
                    'base_currency', 'reciprocal_currency', 'rate', 'base_amount',
                    'reciprocal_amount', 'created_at', 'status']


@admin.register(IncomingTransaction)
class IncomingTransactionAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'transaction_id', 'application', 'mined_at',
                    'block_height', 'status']


@admin.register(Exchange)
class ExchangeAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'transaction_id', 'application', 'mined_at',
                    'block_height', 'status']


@admin.register(Refund)
class RefundAdmin(admin.ModelAdmin):
    list_display = ['id', 'created_at', 'transaction_id', 'application', 'mined_at',
                    'block_height', 'status']


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'created', 'type', 'email', 'is_sended', 'sended']


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
