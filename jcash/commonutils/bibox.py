from typing import Dict, Tuple
from datetime import datetime
import requests

from jcash.settings import ALPHAVANTAGE__API_KEY


PROTOCOL = "https"
HOST = "api.bibox.com"
MARKET_DATA = "mdata"

# request timeout in seconds
TIMEOUT = 15.0


class BiBox:
    """
    See https://github.com/Biboxcom/api_reference/wiki/api_reference for API documentation.
    """

    def build_request_url(self, func_name: str, parameters: Dict=None):

        # the basic url
        url = "{}://{}/v1/{}?".format(PROTOCOL, HOST, func_name)

        # append parameters to the URL.
        if parameters:
            url = "{}&{}".format(url, self._build_parameters(parameters))

        return url

    def get_price(self, base_currency, reciprocal_currency: str) -> Tuple[datetime, float]:
        """
        GET /v1/{func_name}?cmd=market&pair={base_currency}_{reciprocal_currency}

        { "result":
            {
                "id":89,
                "coin_symbol":"JNT",
                "currency_symbol":"ETH",
                "last":"0.00032315",
                "high":"0.00036951",
                "low":"0.00031650",
                "change":"+0.00000469",
                "percent":"+1.47%",
                "vol24H":"1627172",
                "amount":"545.85",
                "last_cny":"0.60",
                "high_cny":"0.69",
                "low_cny":"0.59",
                "last_usd":"0.08",
                "high_usd":"0.10",
                "low_usd":"0.08"
            },
        "cmd":"market"
        }
        """

        data = self._get(self.build_request_url(MARKET_DATA, {'cmd': 'market',
                                                              'pair': '{}_{}'.format(
                                                                  base_currency,
                                                                  reciprocal_currency)
                                                              }))

        rate_datetime = datetime.now()

        rate_value = float(data['result']['last_usd'])

        return rate_datetime, rate_value

    def _get(self, url: str):
        return requests.get(url, timeout=TIMEOUT).json()

    def _build_parameters(self, parameters: Dict):
        # sort the keys so we can test easily in Python 3.3 (dicts are not ordered)
        keys = list(parameters.keys())

        return '&'.join(['{}={}'.format(k, parameters[k]) for k in keys])
