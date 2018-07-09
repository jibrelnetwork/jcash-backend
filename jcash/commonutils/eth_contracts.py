import time
import logging
import json

from django.db import transaction

from .eth_utils import create_web3
from jcash.settings import (
    ETH_TX__BLOCKS_CONFIRM_NUM,
    ETH_TX__GAZ_MULTIPLICATOR,
    ETH_NODE__CHAIN_ID,
    ETH_MANAGER__PRIVATE_KEY,
    ETH_MANAGER__ADDRESS,
    ETH_EXCHANGER__PRIVATE_KEY,
    ETH_EXCHANGER__ADDRESS,
    ETH_LICENSE_REGISTRY_MANAGEMENT__ABI
)
from jcash.api.models import Refund, Exchange, TransactionStatus


def __waitTxConfirmation(tx_id):
    pollingInterval = 2
    maxTimeoutSec = 5 * 60
    maxTimeoutBlocks = 20

    web3 = create_web3()

    if ETH_TX__BLOCKS_CONFIRM_NUM <= 0:
        return

    startTime  = time.time()
    startBlock = web3.eth.blockNumber

    while True:
        transactionReceipt = web3.eth.getTransactionReceipt(tx_id)
        currentBlockNumber = web3.eth.blockNumber

        if transactionReceipt is not None and transactionReceipt.status == 0:
            raise Exception("Transaction {} failed".format(tx_id))

        if not transactionReceipt is None and \
                (currentBlockNumber - transactionReceipt.blockNumber >= ETH_TX__BLOCKS_CONFIRM_NUM - 1):
            if transactionReceipt.status == 1:
                return

        if time.time() > startTime + maxTimeoutSec:
            raise Exception("Transaction {} not minted in {} seconds".format(tx_id, maxTimeoutSec))

        if currentBlockNumber > startBlock + maxTimeoutBlocks:
            raise Exception("Transaction {} not minted in {} blocks".format(tx_id, maxTimeoutBlocks))

        time.sleep(pollingInterval)


def __sendRawTx(_abi, _to, _from, _functionName, _args, _from_priv_key, _nonce = None) -> str:
    web3 = create_web3()

    contract = web3.eth.contract(address=web3.toChecksumAddress(_to), abi=_abi)
    contract_func = getattr(contract.functions, _functionName)

    _tx_gas_price = int(web3.eth.gasPrice  * ETH_TX__GAZ_MULTIPLICATOR)
    _tx_gas_limit = 100000 #contract_func(*_args).estimateGas()

    if _nonce is None:
        _nonce = web3.eth.getTransactionCount(_from)

    _txn = contract_func(*_args).buildTransaction({'chainId': ETH_NODE__CHAIN_ID,
                                                  'gas': _tx_gas_limit,
                                                  'gasPrice': _tx_gas_price,
                                                  'nonce': _nonce})
    _signed_txn = web3.eth.account.signTransaction(_txn, private_key=_from_priv_key)

    _tx_id = web3.toHex(web3.eth.sendRawTransaction(_signed_txn.rawTransaction))
    logging.getLogger(__name__).info("submited transaction tx_id:{}".format(_tx_id))
    return _tx_id


def __sendRawTxAndWait(_abi, _to, _from, _functionName, _args, _from_priv_key) -> str:
    _tx_id = __sendRawTx(_abi, _to, _from, _functionName, _args, _from_priv_key)
    __waitTxConfirmation(_tx_id)


def admitUser(license_registry_address, user_address):
    from web3.auto import w3
    _tx_id = __sendRawTxAndWait(json.loads(ETH_LICENSE_REGISTRY_MANAGEMENT__ABI),
                                license_registry_address,
                                ETH_MANAGER__ADDRESS,
                                "admitUser",
                                ( w3.toChecksumAddress(user_address), ),
                                ETH_MANAGER__PRIVATE_KEY)


def grantUserLicense(license_registry_address, user_address, license_name, expiration_time):
    from web3.auto import w3
    _tx_id = __sendRawTxAndWait(json.loads(ETH_LICENSE_REGISTRY_MANAGEMENT__ABI),
                                license_registry_address,
                                ETH_MANAGER__ADDRESS,
                                "grantUserLicense",
                                ( w3.toChecksumAddress(user_address), license_name, expiration_time),
                                ETH_MANAGER__PRIVATE_KEY)


def licenseUser(license_registry_address, user_address, expiration_time):
    license_names_list = [
        'transfer_funds',
        'receive_funds',
        #'grant_approval',
        #'get_approval',
        #'spend_funds',
    ]

    for license_name in license_names_list:
        grantUserLicense(license_registry_address,
                         user_address,
                         license_name,
                         expiration_time)

    admitUser(license_registry_address, user_address)

    logging.getLogger(__name__).info("licensed address {} expiration {}".format(user_address, expiration_time))


def __transferEth(abi, contract_address, tx_hash, token_address, to_address, value: float, nonce: int) -> str:
    from web3.auto import w3

    _value_wei = w3.toWei(value, 'ether')
    _tx_id = __sendRawTx(abi,
                         contract_address,
                         ETH_EXCHANGER__ADDRESS,
                         "transferEth",
                         (w3.toBytes(hexstr=tx_hash), w3.toChecksumAddress(to_address), _value_wei),
                         ETH_EXCHANGER__PRIVATE_KEY,
                         nonce)
    return _tx_id


def __transferToken(abi, contract_address, tx_hash, token_address, to_address, value: float, nonce: int) -> str:
    from web3.auto import w3

    _value_wei = w3.toWei(value, 'ether')
    _tx_id = __sendRawTx(abi,
                         contract_address,
                         ETH_EXCHANGER__ADDRESS,
                         "transferToken",
                         (w3.toBytes(hexstr=tx_hash), w3.toChecksumAddress(token_address),
                          w3.toChecksumAddress(to_address), _value_wei),
                         ETH_EXCHANGER__PRIVATE_KEY,
                         nonce)
    return _tx_id


def __refundEth(abi, contract_address, tx_hash, token_address, to_address, value: float, nonce: int) -> str:
    from web3.auto import w3

    _value_wei = w3.toWei(value, 'ether')
    _tx_id = __sendRawTx(abi,
                         contract_address,
                         ETH_EXCHANGER__ADDRESS,
                         "refundEth",
                         (w3.toBytes(hexstr=tx_hash), w3.toChecksumAddress(to_address), _value_wei),
                         ETH_EXCHANGER__PRIVATE_KEY,
                         nonce)
    return _tx_id


def __refundToken(abi, contract_address, tx_hash, token_address, to_address, value: float, nonce: int) -> str:
    from web3.auto import w3

    _value_wei = w3.toWei(value, 'ether')
    _tx_id = __sendRawTx(abi,
                         contract_address,
                         ETH_EXCHANGER__ADDRESS,
                         "refundToken",
                         (w3.toBytes(hexstr=tx_hash), w3.toChecksumAddress(token_address),
                          w3.toChecksumAddress(to_address), _value_wei),
                         ETH_EXCHANGER__PRIVATE_KEY,
                         nonce)
    return _tx_id


def send_outgoing_transaction(tx_pk: int,
                              contract_abi: str,
                              contract_address: str,
                              tx_hash: str,
                              token_address: str,
                              to_address: str,
                              value: float,
                              nonce: int,
                              is_refund=False,
                              tx_fn=None):
    try:
        if is_refund:
            entry = Refund.objects.get(pk=tx_pk)
        else:
            entry = Exchange.objects.get(pk=tx_pk)

    except Refund.DoesNotExist:
        logging.getLogger(__name__).info("outgoing with id {} does not exist".format(tx_pk))
        return
    with transaction.atomic():
        tx_hash = tx_fn(contract_abi, contract_address, tx_hash, token_address, to_address, value, nonce)
        entry.status = TransactionStatus.pending
        entry.transaction_id = tx_hash
        entry.save()
        logging.getLogger(__name__).info("outgoing tx with id {} successfully processed".format(tx_pk))


def transferEth(tx_pk: int,
             contract_abi: str,
             contract_address: str,
             tx_hash: str,
             token_address: str,
             to_address: str,
             value: float,
             nonce: int,
             is_refund=False):
    send_outgoing_transaction(tx_pk,
                              contract_abi,
                              contract_address,
                              tx_hash,
                              token_address,
                              to_address.lower(),
                              value,
                              nonce,
                              is_refund,
                              __transferEth)


def transferToken(tx_pk: int,
                  contract_abi: str,
                  contract_address: str,
                  tx_hash: str,
                  token_address: str,
                  to_address: str,
                  value: float,
                  nonce: int,
                  is_refund=False):
    send_outgoing_transaction(tx_pk,
                              contract_abi,
                              contract_address,
                              tx_hash,
                              token_address,
                              to_address.lower(),
                              value,
                              nonce,
                              is_refund,
                              __transferToken)


def refundEth(tx_pk: int,
              contract_abi: str,
              contract_address: str,
              tx_hash: str,
              token_address: str,
              to_address: str,
              value: float,
              nonce: int,
              is_refund=True):
    send_outgoing_transaction(tx_pk,
                              contract_abi,
                              contract_address,
                              tx_hash,
                              token_address,
                              to_address.lower(),
                              value,
                              nonce,
                              is_refund,
                              __refundEth)


def refundToken(tx_pk: int,
                contract_abi: str,
                contract_address: str,
                tx_hash: str,
                token_address: str,
                to_address: str,
                value: float,
                nonce: int,
                is_refund=True):
    send_outgoing_transaction(tx_pk,
                              contract_abi,
                              contract_address,
                              tx_hash,
                              token_address,
                              to_address.lower(),
                              value,
                              nonce,
                              is_refund,
                              __refundToken)
