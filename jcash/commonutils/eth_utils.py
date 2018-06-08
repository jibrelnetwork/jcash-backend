from web3 import Web3, HTTPProvider

from jcash.settings import ETH_NODE__URL


def create_web3() -> Web3:
    return Web3(HTTPProvider(ETH_NODE__URL))


def getTransactionInfo(transaction_id):
    return create_web3().eth.getTransactionReceipt(transaction_id)
