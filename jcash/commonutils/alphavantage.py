from typing import Dict, Tuple
from datetime import datetime
import requests

from jcash.settings import ALPHAVANTAGE__API_KEY


PROTOCOL = "https"
HOST = "www.alphavantage.co"
CURRENCY_RATE = "CURRENCY_EXCHANGE_RATE"

# request timeout in seconds
TIMEOUT = 15.0


class Alphavantage:
    """
    See https://www.alphavantage.co/documentation/ for API documentation.
    """

    def build_request_url(self, func_name: str, parameters: Dict=None):

        # the basic url
        url = "{}://{}/query?function={}".format(PROTOCOL, HOST, func_name)

        # append parameters to the URL.
        if parameters:
            url = "{}&{}".format(url, self._build_parameters(parameters))

        return url

    def get_price(self, base_currency, reciprocal_currency: str) -> Tuple[datetime, float]:
        """
        GET /query?function={func_name}&from_currency=USD&to_currency={symbol}&apikey={apikey}

        {
            "Realtime Currency Exchange Rate": {
                "1. From_Currency Code": "USD",
                "2. From_Currency Name": "United States Dollar",
                "3. To_Currency Code": "AED",
                "4. To_Currency Name": "United Arab Emirates Dirham",
                "5. Exchange Rate": "3.67322400",
                "6. Last Refreshed": "2018-05-03 08:00:05",
                "7. Time Zone": "UTC"
            }
        }
        """

        data = self._get(self.build_request_url(CURRENCY_RATE, {'from_currency': base_currency,
                                                                'to_currency': reciprocal_currency,
                                                                'apikey': ALPHAVANTAGE__API_KEY}))

        rate_datetime = datetime.strptime(data['Realtime Currency Exchange Rate']['6. Last Refreshed'],
                                          '%Y-%m-%d %H:%M:%S')
        rate_value = float(data['Realtime Currency Exchange Rate']['5. Exchange Rate'])

        return rate_datetime, rate_value

    def _get(self, url: str):
        return requests.get(url, timeout=TIMEOUT).json()

    def _build_parameters(self, parameters: Dict):
        # sort the keys so we can test easily in Python 3.3 (dicts are not ordered)
        keys = list(parameters.keys())
        #keys.sort()

        return '&'.join(['{}={}'.format(k, parameters[k]) for k in keys])
