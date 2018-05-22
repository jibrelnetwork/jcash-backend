from datetime import datetime
from django.db import transaction
import logging
import sys
import traceback

from .bitfinex import Bitfinex
from .alphavantage import Alphavantage
from jcash.api.models import Currency, CurrencyPair, CurrencyPairRate


def fetch_crypto_price(base_currency: str, reciprocal_currency: str, symbol: str):
    """
    Fetch exchangeable currency price.
    :param base_currency:
    :param reciprocal_currency:
    :param symbol:
    """
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start to fetch {}/{} conversion rate from the Bitfinex"
                                         .format(base_currency, reciprocal_currency))

        bitfinex = Bitfinex()
        ticker_data = bitfinex.get_ticker(symbol)

        currency_pair = CurrencyPair.objects.filter(base_currency=base_currency,reciprocal_currency=reciprocal_currency).first()

        if not currency_pair:
            logging.getLogger(__name__).error("The currency pair '{}/{}' does not exists."
                                              .format(base_currency, reciprocal_currency))
        elif "bid" in ticker_data.keys() and "timestamp" in ticker_data.keys():
            price_datetime = datetime.utcfromtimestamp(ticker_data["timestamp"])
            price_value = float(ticker_data["bid"])

            with transaction.atomic():
                currency_pair_rate = CurrencyPairRate.objects.create(currency_pair=currency_pair,
                                                                     value=price_value,
                                                                     created_at=price_datetime)
                currency_pair_rate.save()

            logging.getLogger(__name__).info("Success for symbol '{}'.".format(symbol))
        else:
            logging.getLogger(__name__).error("Invalid response from Bitfinex API for symbol '{}'."
                                              .format(symbol))

        logging.getLogger(__name__).info("Finished to fetch {}/{} conversion rate from the Bitfinex"
                                         .format(base_currency, reciprocal_currency))

    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Finished to fetch {}/{} conversion rate from the Bitfinex due to error:\n{}"
                                          .format(base_currency, reciprocal_currency, exception_str))


def fetch_fx_price(base_currency: str, reciprocal_currency: str):
    """
    Fetch currency price from alphavantage.
    :param base_currency:
    :param reciprocal_currency:
    """
    # noinspection PyBroadException
    try:
        logging.getLogger(__name__).info("Start to fetch {}/{} conversion rate from the Alphavantage"
                                         .format(base_currency, reciprocal_currency))

        alphavanatage = Alphavantage()
        ticker_data = alphavanatage.get_price(base_currency, reciprocal_currency)

        currency_pair = CurrencyPair.objects.filter(base_currency=base_currency,
                                                    reciprocal_currency=reciprocal_currency).first()

        if not currency_pair:
            logging.getLogger(__name__).error("The currency pair '{}/{}' does not exists."
                                              .format(base_currency, reciprocal_currency))
        else:
            with transaction.atomic():
                currency_pair_rate = CurrencyPairRate.objects.create(currency_pair=currency_pair,
                                                                     created_at=ticker_data[0],
                                                                     value=float(ticker_data[1]))
                currency_pair_rate.save()

        logging.getLogger(__name__).info("Success for symbol '{}/{}'.".format(base_currency, reciprocal_currency))

        logging.getLogger(__name__).info("Finished to fetch '{}/{}' conversion rate from the Alphavantage"
                                         .format(base_currency, reciprocal_currency))

    except Exception:
        exception_str = ''.join(traceback.format_exception(*sys.exc_info()))
        logging.getLogger(__name__).error("Finished to fetch {}/{} conversion rate from the Bitfinex due to error:\n{}"
                                          .format(base_currency, reciprocal_currency, exception_str))


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

        with transaction.atomic():
            currency_pair_rate = CurrencyPairRate.objects.create(currency_pair=currency_pair,
                                                                 created_at=price_pair_datetime,
                                                                 buy_price=price_pair_value,
                                                                 sell_price=price_pair_value)  # todo: calc rate
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
