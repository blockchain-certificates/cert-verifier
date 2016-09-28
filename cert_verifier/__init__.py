"""
Verify blockchain certificates (http://www.blockcerts.org/)
"""
import binascii
import sys
from enum import Enum

from cert_verifier.errors import *


unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    def unhexlify(h): return binascii.unhexlify(h.encode('utf8'))


    def hexlify(b): return binascii.hexlify(b).decode('utf8')


class Chain(Enum):
    mainnet = 1
    testnet = 2


def parse_chain_from_address(address):
    if address.startswith('1'):
        return Chain.mainnet
    elif address.startswith('m') or address.startswith('n'):
        return Chain.testnet
    else:
        raise UnrecognizedChainError('Unrecognized bitcoin address')


StepStatus = Enum('StepStatus', ['not_started', 'done', 'passed', 'failed'])

# {
#   [
#     {
#       'name': step_name_1,
#       'status': status,
#       'details': details
#     },
#     ...
#   ]
# }