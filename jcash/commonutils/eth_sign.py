from web3.auto import w3
from eth_account.messages import defunct_hash_message
from hexbytes import HexBytes


def signMessage(message: str, private_key: str) -> str:
    """
    Sign the message provided.

    :param message: message string to sign
    :param private_key: private key
    :return: signature
    """
    private_key_hb = HexBytes(private_key)
    message_hash = defunct_hash_message(text=message)
    signed_message = w3.eth.account.signHash(message_hash, private_key=bytes(private_key_hb))

    return signed_message['signature']


def verifySign(message: str, signature: str, pub_address: str) -> bool:
    """
    Verify signature.

    :param message: original message string.
    :param signature: signature hex string.
    :param public_key: pub address who signed a message string.
    :return: True if signature is right otherwise False
    """
    message_hash = defunct_hash_message(text=message)

    return w3.eth.account.recoverHash(message_hash, signature=signature).lower() == pub_address.lower()
