"""
Connectors supporting Bitcoin transaction lookups. This is used in the Blockchain Certificates project
(http://www.blockcerts.org/) for validating certificates on the blockchain.
"""
import logging

import requests

from cert_verifier.errors import *
from cert_verifier import Chain


def createTransactionLookupConnector(chain=Chain.mainnet):
    """
    Use Blockcypher by default for now
    :param chain: which chain, supported values are testnet and mainnet
    :return: connector for looking up transactions
    """
    return BlockcypherConnector(chain)


class TransactionLookupConnector:
    """
    Abstract connector for looking up transactions
    """

    def lookup_tx(self, txid):
        """
        Abstract method for looking up a transaction by transaction id
        :param txid: transaction id
        :return: TransactionData
        """
        return None


class BlockchainInfoConnector(TransactionLookupConnector):
    """
    Lookup blockchain transactions using blockchain.info api. Currently only the 'mainnet' chain is supported in this
    connector.
    """

    def __init__(self, chain=Chain.mainnet):
        if chain != Chain.mainnet:
            raise Exception('only mainnet chain is supported with blockchain.info collector')
        self.url = 'https://blockchain.info/rawtx/%s?cors=true'

    def lookup_tx(self, txid):
        r = requests.get(self.url % txid)
        if r.status_code != 200:
            logging.error('Error looking up by transaction_id=%s, status_code=%d', txid, r.status_code)
            raise InvalidTransactionError('error looking up transaction_id=%s' % txid)
        else:
            revoked = set()
            script = None
            for o in r.json()['outs']:
                if int(o.get('value', 1)) == 0:
                    script = o['script']
                else:
                    if o.get('spent'):
                        revoked.add(o.get('addr'))
            if not script:
                raise InvalidTransactionError('transaction with transaction_id=%s is missing op_return script' % txid)
            return TransactionData(revoked, script)


class BlockcypherConnector(TransactionLookupConnector):
    """
    Lookup blockchain transactions using blockcypher api. Currently the 'mainnet' and 'testnet' chains are supported in
    this connector.
    """

    def __init__(self, chain):
        if chain == Chain.testnet:
            self.url = 'http://api.blockcypher.com/v1/btc/test3/txs/%s'
        elif chain == Chain.mainnet:
            self.url = 'https://api.blockcypher.com/v1/btc/main/txs/%s'
        else:
            raise Exception(
                'unsupported chain (%s) requested with blockcypher collector. Currently only testnet and mainnet are supported' % chain)

    def lookup_tx(self, txid):
        r = requests.get(self.url % txid)
        if r.status_code != 200:
            logging.error('Error looking up by transaction_id=%s, status_code=%d', txid, r.status_code)
            raise InvalidTransactionError('error looking up transaction_id=%s' % txid)
        else:
            revoked = set()
            script = None
            for o in r.json()['outputs']:
                if int(o.get('value', 1)) == 0:
                    script = o['script']
                else:
                    if o.get('spent_by'):
                        revoked.add(o.get('addresses')[0])
            if not script:
                raise InvalidTransactionError('transaction with transaction_id=%s is missing op_return script' % txid)
            return TransactionData(revoked, script)


class TransactionData:
    """
    If the blockchain transaction was found, this will be populated with the op_return script, and a set of revoked
    addresses. These are the key parts of the transaction lookup that we need in validation.

    TransactionLookupConnector implementations return this object to shield the caller from api-specific json parsing.
    """

    def __init__(self, revoked_addresses, op_return_script):
        self.revoked_addresses = revoked_addresses
        self.script = op_return_script
