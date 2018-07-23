import logging
import requests

from jcash import settings
from jcash.commonutils.app_init import initialize_app
from jcash.celeryapp import celery_app


GA_URL = "http://www.google-analytics.com/collect"
logger = logging.getLogger(__name__)


class GAClient:

    def __init__(self, ga_id, account):
        self.ga_id = ga_id
        self.account = account
        self.cid = account.tracking.get('ga_id')
        self.cd2 = "{0:%d/%m/%y}".format(account.created_at)

    def send_status(self, status):
        """
        v=1&t=event&tid=UA-103798122-1&cid=1734424917.1494941541&ec=TokensRequest&ea=Status&el=Verified
        &cn=campaign&cs=source&cm=medium&ck=keyword&cc=content&cd2=registration_date
        """
        data = {
            'v': '1',
            't': 'event',  #=event
            'tid': self.ga_id,  #=UA-103798122-1
            'cid': self.cid,  #=1734424917.1494941541
            'ec': 'TokensRequest',  #=TokensRequest
            'ea': 'Status',  #=Status
            'el': status,  #=Verified
        }
        logger.info("Sending GA event data for user %s: %s", self.account.user.pk, data)
        self.send_data(data)

    def send_transaction(self, transaction_id, summ, currency):
        """
        v=1&t=transaction&tid=UA-103798122-1&cid=1.2.894891330.1494586649&ti=12345
        &tr=14500.123&cu=USD&cn=campaign&cs=source&cm=medium&ck=keyword&cc=content
        cd2=registration_date
        """
        data = {
            'v': '1',  #=1
            't': 'transaction',  #=transaction
            'tid': self.ga_id,  #=UA-103798122-1
            'cid': self.cid,  #=1.2.894891330.1494586649
            'ti': transaction_id,  #=12345
            'tr': summ,  #=14500.123
            'cu': currency,  #=USD
        }
        logger.info("Sending GA TX data for user %s: %s", self.account.user.pk, data)
        self.send_data(data)

    def send_item(self, transaction_id, quantity, item_price, currency):
        """
        v=1&t=item&tid=UA-103798122-1&cid=1.2.894891330.1494586649&ti=12345
        &in=JibrelTokens&ip=14500.123&iq=1&1c=qweqeq&
        iv=phones&cn=campaign&cs=source&cm=medium&ck=keyword&cc=content
        &cd2=registration_date
        """
        data = {
            'v': '1',  #=1
            't': 'item',  #=item
            'tid': self.ga_id,  #=UA-103798122-1
            'cid': self.cid,  #=1.2.894891330.1494586649
            'ti': transaction_id,  #=12345
            'in': currency,  #=jAED
            'ip': item_price,  #=14500.123
            'iq': quantity,  #=1
            '1c': '1111',  #=qweqeq
            'iv': 'Tokens',  #=phones
        }
        logger.info("Sending GA Item data for user %s: %s", self.account.user.pk, data)
        self.send_data(data)

    def send_tx_with_item(self, in_tx_id, in_currency, summ,
                          out_tx_id, out_currency, quantity, item_price):
        self.send_transaction(in_tx_id, summ, in_currency)
        self.send_item(out_tx_id, quantity, item_price, out_currency)

    def make_utm_params(self, tracking_params):
        tp = tracking_params
        utm = {
            'cn': tp.get('utm_campaign', ''),  #=campaign
            'cs': tp.get('utm_source', ''),  #=source
            'cm': tp.get('utm_medium', ''),  #=medium
            'ck': tp.get('utm_keyword', ''),  #=keyword
            'cc': tp.get('utm_content', ''),  #=content
            'cd2': self.cd2, #=registration_date
        }
        for k, v in list(utm.items()):
            if not v:
                del utm[k]
        return utm

    def send_data(self, data):
        if not self.cid:
            logger.warn("No GA client ID for user #%s", self.account.user.pk)
            return
        utm = self.make_utm_params(self.account.tracking)
        data.update(utm)
        send_ga_request_async.delay(GA_URL, data)


def get_ga_client(account):
    client = GAClient(settings.GA_ID, account)
    return client


def on_status_new(account):
    get_ga_client(account).send_status('New')


def on_status_registration_complete(account):
    get_ga_client(account).send_status('RegistrationComplete')


def on_status_verified_manual(account):
    get_ga_client(account).send_status('Verified')


def on_status_not_verified_manual(account):
    get_ga_client(account).send_status('NotVerified')


def on_exchange_completed(application):
    account = application.user.account
    in_tx = application.incoming_txs.latest('created_at')
    exchange_tx = application.exchanges.latest('created_at')

    get_ga_client(account).send_status('SuccessBuy')
    get_ga_client(account).send_tx_with_item(in_tx.transaction_id, application.base_currency,
                                             in_tx.value, exchange_tx.transaction_id,
                                             application.reciprocal_currency,
                                             exchange_tx.value, application.rate)


@celery_app.task(autoretry_for=(requests.RequestException,))
@initialize_app
def send_ga_request_async(url, data):
    logger.info('Sending GA request. Data: %s', data)
    requests.post(url, data)
    logger.info('GA request sent')
