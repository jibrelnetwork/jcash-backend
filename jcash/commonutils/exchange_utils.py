
def get_exchange_currency_by_application(application):
    """
    Returns currency for exchange op
    :param application:
    :return: currency id
    """
    if application.is_reverse:
        return application.currency_pair.base_currency.pk
    else:
        return application.currency_pair.reciprocal_currency.pk


def get_refund_currency_by_application(application):
    """
    Returns currency for refund op
    :param application:
    :return: currency id
    """
    if application.is_reverse:
        return application.currency_pair.reciprocal_currency.pk
    else:
        return application.currency_pair.base_currency.pk
