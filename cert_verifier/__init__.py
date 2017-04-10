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

StepStatus = Enum('StepStatus', ['not_started', 'done', 'passed', 'failed'])


class TransactionData:
    """
    If the blockchain transaction was found, this will be populated with the op_return script, and a set of revoked
    addresses. These are the key parts of the transaction lookup that we need in validation.

    TransactionLookupConnector implementations return this object to shield the caller from api-specific json parsing.
    """

    def __init__(self, op_return, date_time_utc, revoked_addresses):
        self.op_return = op_return
        self.date_time_utc = date_time_utc
        self.revoked_addresses = revoked_addresses
