from datetime import datetime
from django.db import transaction
import logging
import sys
import traceback

from .bitfinex import Bitfinex
from .alphavantage import Alphavantage
from jcash.api.models import Currency, CurrencyPair, CurrencyPairRate


def feth_currency_price():
    currency_pairs = CurrencyPair.objects.filter(is_exchangeable=True)
    for pair in currency_pairs:
        fetch_exchangeable_currency_price(pair)


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

        bitfinex = Bitfinex()
        ticker_data_base = bitfinex.get_ticker("{}{}".format(currency_pair.base_currency.symbol, usd_symbol).lower())

        alphavanatage = Alphavantage()
        ticker_data_recip = alphavanatage.get_price(usd_symbol, currency_pair.reciprocal_currency.symbol)

        if not "bid" in ticker_data_base.keys() or not "timestamp" in ticker_data_base.keys():
            logging.getLogger(__name__).error("Invalid response from Bitfinex API for symbol '{}/{}'."
                                              .format(currency_pair.base_currency.display_name, usd_symbol))
            return

        if not ticker_data_recip or len(ticker_data_recip)!=2:
            logging.getLogger(__name__).error("Invalid response from Alphavantage API for symbol '{}/{}'."
                                              .format(usd_symbol, currency_pair.reciprocal_currency.display_name))
            return

        price_datetime_base = datetime.utcfromtimestamp(ticker_data_base["timestamp"])
        price_value_base = float(ticker_data_base["bid"])
        price_datetime_recip = ticker_data_recip[0]
        price_value_recip = float(ticker_data_recip[1])
        price_pair_datetime = max(price_datetime_base, price_datetime_recip)
        price_pair_value = price_value_base * price_value_recip
        price_pair_value_buy = price_pair_value + 10;  # todo: calc rate
        price_pair_value_sell = price_pair_value - 10;  # todo: calc rate

        with transaction.atomic():
            currency_pair_rate = CurrencyPairRate.objects.create(currency_pair=currency_pair,
                                                                 created_at=price_pair_datetime,
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
