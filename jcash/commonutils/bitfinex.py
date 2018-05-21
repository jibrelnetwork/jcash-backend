from typing import Dict, Optional
import requests

PROTOCOL = "https"
HOST = "api.bitfinex.com"
VERSION = "v1"

PATH_SYMBOLS = "symbols"
PATH_TICKER = "ticker/%s"

# request timeout in seconds
TIMEOUT = 15.0


class Bitfinex:
    """
    See https://www.bitfinex.com/pages/api for API documentation.
    """

    def base_url(self):
        return u"{0:s}://{1:s}/{2:s}".format(PROTOCOL, HOST, VERSION)

    def build_request_url(self, path, path_arg: Optional[str] = None, parameters=None):

        # the basic url
        url = "%s/%s" % (self.base_url(), path)

        if path_arg:
            url = url % path_arg

        # append parameters to the URL.
        if parameters:
            url = "%s?%s" % (url, self._build_parameters(parameters))

        return url

    def get_symbols(self):
        """
        GET /symbols

        curl https://api.bitfinex.com/v1/symbols
        ['btcusd','ltcusd','ltcbtc']
        """
        return self._get(self.build_request_url(PATH_SYMBOLS))

    def get_ticker(self, symbol):
        """
        GET /ticker/:symbol

        curl https://api.bitfinex.com/v1/ticker/btcusd
        {
            'ask': '562.9999',
            'timestamp': '1395552290.70933607',
            'bid': '562.25',
            'last_price': u'562.25',
            'mid': u'562.62495'
        }
        """
        data = self._get(self.build_request_url(PATH_TICKER, symbol))

        # convert all values to floats
        return self._convert_to_floats(data)

    def _convert_to_floats(self, data: Dict):
        """
        convert all dict values to floats
        """
        for key, value in data.items():
            data[key] = float(value)

        return data

    def _get(self, url: str):
        return requests.get(url, timeout=TIMEOUT).json()

    def _build_parameters(self, parameters: Dict):
        # sort the keys so we can test easily in Python 3.3 (dicts are not ordered)
        keys = list(parameters.keys())
        keys.sort()

        return '&'.join(["%s=%s" % (k, parameters[k]) for k in keys])