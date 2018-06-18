
def round_amount(value: float, currency_pair, is_reverse_operation: bool, is_base=True) -> float:
    """
    Round value by currency settings
    :param value: value of exchange operation
    :param currency_pair: CurrencyPair of exchange operation
    :param is_reverse_operation: sign if it's reverse exchange operation
    :param is_base: sign if it's base_amount of exchange operation
    :return: float
    """
    if (is_base):
        rounded_value = round(value,
                              currency_pair.reciprocal_currency.round_digits \
                                  if is_reverse_operation else \
                                  currency_pair.base_currency.round_digits)
    else:
        rounded_value = round(value,
                              currency_pair.base_currency.round_digits \
                                  if is_reverse_operation else \
                                  currency_pair.reciprocal_currency.round_digits)
    return rounded_value


def calc_reverse_rate(rate: float) -> float:
    """
    Calc reverse exchange operation rate
    :param rate: canonical rate
    :return: float
    """
    return 1.0 / rate


def calc_reciprocal_amount(base_amount: float, exchange_rate: float) -> float:
    """
    Calc reciprocal amount by base amount and exchange rate
    :param base_amount: float value
    :param exchange_rate: float value
    :return: float
    """
    return base_amount * exchange_rate


def calc_base_amount(reciprocal_amount: float, exchange_rate: float) -> float:
    """
    Calc base amount by reciprocal amount and exchange rate
    :param reciprocal_amount: float value
    :param exchange_rate: float value
    :return: float
    """
    return reciprocal_amount / exchange_rate


def calc_absolute_difference(value1, value2) -> float:
    """
    Calc absolute difference
    :param value1:
    :param value2:
    :return: difference in percent
    """
    return abs(value1 - value2) / value2 * 100


def check_amount_limit(value: float, currency_pair, is_reverse_operation, is_base = True) -> bool:
    """
    Check that amount value is greater or equal currency limits
    :param value:
    :param currency_pair: CurrencyPair of exchange operation
    :param is_reverse_operation: sign if it's reverse operation
    :param is_base: sign if it's base amount
    :return: bool
    """
    result = False
    if is_base:
        if is_reverse_operation:
            if value >= currency_pair.reciprocal_currency.min_limit and \
                value <= currency_pair.reciprocal_currency.max_limit:
                result = True
        else:
            if value >= currency_pair.base_currency.min_limit and \
                value <= currency_pair.base_currency.max_limit:
                result = True
    else:
        if is_reverse_operation:
            if value >= currency_pair.base_currency.min_limit and \
                value <= currency_pair.base_currency.max_limit:
                result = True
        else:
            if value >= currency_pair.reciprocal_currency.min_limit and \
                value <= currency_pair.reciprocal_currency.max_limit:
                result = True

    return result
