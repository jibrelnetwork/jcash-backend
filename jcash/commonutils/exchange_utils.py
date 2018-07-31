from django.db.models import Sum

from jcash.api.models import Currency, Application, ApplicationStatus


def get_exchange_currency_by_application(application: Application):
    """
    Returns currency for exchange op
    :param application:
    :return: currency id
    """
    if application.is_reverse:
        return application.currency_pair.base_currency.pk
    else:
        return application.currency_pair.reciprocal_currency.pk


def get_refund_currency_by_application(application: Application):
    """
    Returns currency for refund op
    :param application:
    :return: currency id
    """
    if application.is_reverse:
        return application.currency_pair.reciprocal_currency.pk
    else:
        return application.currency_pair.base_currency.pk


def get_currency_balance(currency: Currency):
    """
    Returns currency balance
    :param currency:
    :return: balance
    """
    active_app_reverse = Application.objects.filter(currency_pair__base_currency=currency,
                                                    is_reverse=True,
                                                    status__in=(
                                                        str(ApplicationStatus.created),
                                                        str(ApplicationStatus.confirming),
                                                        str(ApplicationStatus.waiting),
                                                        str(ApplicationStatus.refunding),
                                                            str(ApplicationStatus.converting))
                                                        ).aggregate(Sum('reciprocal_amount_actual'))
    active_app_reverse_sum = active_app_reverse['reciprocal_amount_actual__sum'] \
        if active_app_reverse['reciprocal_amount_actual__sum'] else 0.0

    active_app = Application.objects.filter(currency_pair__reciprocal_currency=currency,
                                            is_reverse=False,
                                            status__in=(
                                                str(ApplicationStatus.created),
                                                str(ApplicationStatus.confirming),
                                                str(ApplicationStatus.waiting),
                                                str(ApplicationStatus.refunding),
                                                str(ApplicationStatus.converting))
                                            ).aggregate(Sum('reciprocal_amount_actual'))
    active_app_sum = active_app['reciprocal_amount_actual__sum'] \
        if active_app['reciprocal_amount_actual__sum'] else 0.0

    return currency.balance - active_app_sum - active_app_reverse_sum
