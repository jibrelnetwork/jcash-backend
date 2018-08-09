from web3 import Web3, HTTPProvider

from jcash.settings import ETH_NODE__URL, ETH_EXCHANGER__ADDRESS


def create_web3() -> Web3:
    return Web3(HTTPProvider(ETH_NODE__URL))


def get_exchanger_nonce() -> int:
    return create_web3().eth.getTransactionCount(Web3.toChecksumAddress(ETH_EXCHANGER__ADDRESS))
