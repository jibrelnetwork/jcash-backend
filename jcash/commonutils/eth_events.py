from typing import List, Tuple
from datetime import datetime
from hexbytes import HexBytes
from dateutil.tz import tzlocal

from web3.utils.filters import construct_event_topic_set
from web3.utils.events import get_event_data
from web3.contract import ContractEvents

from .eth_utils import create_web3


def get_incoming_txs(
        contract_address: str,
        exchanger_address: str,
        contract_abi: List,
        event_name: str,
        block_number: int) -> List[Tuple[str,int,datetime,str,str,str,float]]:
    """
    Get incoming transactions
    :param contract_address: address
    :param contract_abi: abi
    :param event_name: event name
    :param block_number: block number
    :return: list of tuple (transaction_hash,block_number,mined_at,event_name,from_address,to_address,value)
    """
    web3 = create_web3()

    contract_abi_json = contract_abi
    contract_events = ContractEvents(contract_abi_json, web3, contract_address)
    event_abi = contract_events[event_name]._get_event_abi()
    topic_set = construct_event_topic_set(event_abi)

    filter = web3.eth.filter({'topics': topic_set[0], 'address': contract_address.lower(), 'fromBlock':block_number})
    logs = web3.eth.getFilterLogs(filter.filter_id)
    result = []
    for log_entry in logs:
        block_number = log_entry['blockNumber']
        block_data = web3.eth.getBlock(block_number)
        transaction_hash = HexBytes(log_entry['transactionHash']).hex()
        mined_at = datetime.fromtimestamp(block_data.timestamp, tzlocal())
        evnt_args = get_event_data(event_abi, log_entry)
        if event_name == 'ReceiveEvent':
            result.append((transaction_hash,
                           block_number,
                           mined_at,
                           event_name,
                           evnt_args.args['from'].lower(),
                           contract_address.lower(),
                           web3.fromWei(evnt_args.args.value, 'ether')))
        elif event_name == 'Transfer' and exchanger_address.lower() == evnt_args.args['to'].lower():
            result.append((transaction_hash,
                           block_number,
                           mined_at,
                           event_name,
                           evnt_args.args['from'].lower(),
                           evnt_args.args['to'].lower(),
                           web3.fromWei(evnt_args.args.value, 'ether')))
    return result


def get_replenishers(
        contract_address: str,
        contract_abi: List,
        block_number: int) -> List[Tuple[str,int,datetime,str,str]]:
    """
    Get replenishers
    :param contract_address: address
    :param contract_abi: abi
    :param block_number: block number
    :return: list of tuple (transaction_hash,block_number,mined_at,event_name,replenisher_address)
    """
    web3 = create_web3()

    event_names = ['ManagerPermissionGrantedEvent', 'ManagerPermissionRevokedEvent']
    contract_abi_json = contract_abi
    contract_events = ContractEvents(contract_abi_json, web3, contract_address)

    result = []

    for event_name in event_names:
        event_abi = contract_events[event_name]._get_event_abi()
        topic_set = construct_event_topic_set(event_abi)

        filter = web3.eth.filter({'topics': topic_set[0], 'address': contract_address.lower(), 'fromBlock':block_number})
        logs = web3.eth.getFilterLogs(filter.filter_id)

        for log_entry in logs:
            block_number = log_entry['blockNumber']
            block_data = web3.eth.getBlock(block_number)
            transaction_hash = HexBytes(log_entry['transactionHash']).hex()
            mined_at = datetime.fromtimestamp(block_data.timestamp, tzlocal())
            evnt_args = get_event_data(event_abi, log_entry)

            if evnt_args.args['permission'] == 'replenish_eth':
                result.append((transaction_hash,
                               block_number,
                               mined_at,
                               event_name,
                               evnt_args.args['manager'].lower()))
    return result


def get_tx_info(tx_hash: str):
    """
    Get tx info
    :param tx_hash: transaction hash
    :return: tuple (tx_receipt_info, block_number)
    """
    web3 = create_web3()

    return web3.eth.getTransactionReceipt(tx_hash), web3.eth.blockNumber
