from datetime import datetime
from django.db import transaction
import logging
import sys
import traceback
from dateutil.tz import tzutc

from .bitfinex import Bitfinex
from .alphavantage import Alphavantage
from .bibox import BiBox
from jcash.api.models import Currency, CurrencyPair, CurrencyPairRate, JntRate


def get_currency_pair_rate(currency_pair_rate: CurrencyPairRate, is_reverse_operation: bool):
    """
    Get currency
    :param currency_pair_rate:
    :param is_reverse_operation: sign if it's reverse exchange operation
    :return: sell_price or buy_price
    """
    return currency_pair_rate.buy_price if is_reverse_operation else \
        currency_pair_rate.sell_price


def fetch_currency_price():
    """
    Fetch currency prices
    """
    currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True)
    for pair in currency_pairs:
        fetch_exchangeable_currency_price(pair)


def calc_buy_rate(base_rate: float, fee_percent: float) -> float:
    """
    Calculate currency pair buy rate
    :param base_rate: rate w/o fee
    :param fee_percent: borrow fee in percent
    :return: buy rate
    """
    return (1 + fee_percent/100.0) * base_rate


def calc_sell_rate(base_rate: float, fee_percent: float) -> float:
    """
    Calculate currency pair sell rate
    :param base_rate: rate w/o fee
    :param fee_percent: borrow fee in percent
    :return: sell rate
    """
    return (1 - fee_percent/100.0) * base_rate


def fetch_exchangeable_currency_price(currency_pair: CurrencyPair):
    """
    Fetch exchangeable currency price.
    :param base_currency:
    :param reciprocal_currency:
    """
    # noinspection PyBroadException
    try:
        usd_symbol = 'USD'
        logging.getLogger(__name__).info("Start to fetch {}/{} conversion rate"
                                         .format(currency_pair.base_currency.display_name,
                                                 currency_pair.reciprocal_currency.display_name))

        if not currency_pair:
            logging.getLogger(__name__).error("The currency pair '{}/{}' does not exists."
                                              .format(currency_pair.base_currency.display_name,
                                                      currency_pair.reciprocal_currency.display_name))
            return

        ticker_data_base = None
        try:
            bitfinex = Bitfinex()
            ticker_data_base = bitfinex.get_ticker("{}{}".format(currency_pair.base_currency.symbol, usd_symbol).lower())
        except:
            logging.getLogger(__name__).info("Fetch currency rate failed from Bitfinex API for symbol '{}/{}'."
                                             .format(currency_pair.base_currency.display_name, usd_symbol))

        ticker_data_recip = None
        try:
            alphavanatage = Alphavantage()
            ticker_data_recip = alphavanatage.get_price(usd_symbol, currency_pair.reciprocal_currency.symbol)
        except:
            logging.getLogger(__name__).info("Fetch currency rate failed from Alphavantage API for symbol '{}/{}'."
                                              .format(currency_pair.reciprocal_currency.display_name, usd_symbol))

        if not ticker_data_base or \
            not "bid" in ticker_data_base.keys() or \
                not "timestamp" in ticker_data_base.keys():
            logging.getLogger(__name__).info("Invalid response from Bitfinex API for symbol '{}/{}'."
                                              .format(currency_pair.base_currency.display_name, usd_symbol))
            return

        if not ticker_data_recip or len(ticker_data_recip)!=2:
            logging.getLogger(__name__).info("Invalid response from Alphavantage API for symbol '{}/{}'."
                                              .format(usd_symbol, currency_pair.reciprocal_currency.display_name))
            return

        price_datetime_base = datetime.utcfromtimestamp(ticker_data_base["timestamp"])
        price_value_base = float(ticker_data_base["bid"])
        price_datetime_recip = ticker_data_recip[0]
        price_value_recip = float(ticker_data_recip[1])
        price_pair_datetime = max(price_datetime_base, price_datetime_recip)
        price_pair_value = price_value_base * price_value_recip
        price_pair_value_buy = calc_buy_rate(price_pair_value, currency_pair.buy_fee_percent)
        price_pair_value_sell = calc_sell_rate(price_pair_value, currency_pair.sell_fee_percent)

        with transaction.atomic():
            currency_pair_rate = CurrencyPairRate.objects.create(currency_pair=currency_pair,
                                                                 created_at=datetime(price_pair_datetime.year,
                                                                                     price_pair_datetime.month,
                                                                                     price_pair_datetime.day,
                                                                                     price_pair_datetime.hour,
                                                                                     price_pair_datetime.minute,
                                                                                     price_pair_datetime.second,
                                                                                     price_pair_datetime.microsecond,
                                                                                     tzinfo=tzutc()),
                                                                 buy_price=price_pair_value_buy,
                                                                 sell_price=price_pair_value_sell)
            currency_pair_rate.save()

        logging.getLogger(__name__).info("Finished to fetch {}/{} conversion rate"
                                         .format(currency_pair.base_currency.display_name,
                                                 currency_pair.reciprocal_currency.display_name))
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Finished to fetch {}/{} conversion rate due to error:\n{}"
                                          .format(currency_pair.base_currency.display_name,
                                                  currency_pair.reciprocal_currency.display_name,
                                                  exception_str))


def fetch_jnt_price():
    """
    Fetch JNT price (USD).
    """
    # noinspection PyBroadException
    try:
        base_cur = 'JNT'
        rec_cur = 'ETH'
        logging.getLogger(__name__).info("Start to fetch {}/{} price"
                                         .format(base_cur, rec_cur))

        ticker_data = None
        try:
            bibox = BiBox()
            ticker_data = bibox.get_price(base_cur, rec_cur)
        except:
            logging.getLogger(__name__).info("Fetch currency rate failed from BiBox API for symbol '{}/{}'."
                                             .format(base_cur, rec_cur))

        if not ticker_data or len(ticker_data) != 2:
            logging.getLogger(__name__).info("Invalid response from BiBox API for symbol '{}/{}'."
                                              .format(base_cur, rec_cur))
            return

        with transaction.atomic():
            jnt_rate = JntRate.objects.create(created_at=ticker_data[0],
                                              price=ticker_data[1],
                                              source='bibox')
            jnt_rate.save()

        logging.getLogger(__name__).info("Finished to fetch {}/{} price"
                                         .format(base_cur, rec_cur))
    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Finished to fetch {}/{} price due to error:\n{}"
                                          .format(base_cur, rec_cur, exception_str))
