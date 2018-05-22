import eth_utils

def is_valid_address(address: str) -> bool:
    """
    Check that an Ethereum addreess is valid.

    :param address: address string
    :return: True if is valid otherwise False
    """

    return eth_utils.is_address(address) \
           and (eth_utils.is_checksum_address(address) or \
                eth_utils.is_normalized_address(address))
