"""
Connectors supporting Bitcoin transaction lookups. This is used in the Blockchain Certificates project
(http://www.blockcerts.org/) for validating certificates on the blockchain.
"""
import logging

import requests

from cert_verifier import Chain
from cert_verifier.errors import *


def createTransactionLookupConnector(chain=Chain.mainnet):
    """
    Use BlockrIoConnector by default for now
    :param chain: which chain, supported values are testnet and mainnet
    :return: connector for looking up transactions
    """
    return BlockcypherConnector(chain)


class TransactionLookupConnector:
    """
    Abstract connector for looking up transactions
    """

    def __init__(self):
        self.url = None

    def lookup_tx(self, txid):
        json_response = self.fetch_tx(txid)
        return self.parse_tx(json_response)

    def fetch_tx(self, txid):
        r = requests.get(self.url % txid)
        if r.status_code != 200:
            logging.error('Error looking up by transaction_id=%s, status_code=%d', txid, r.status_code)
            raise InvalidTransactionError('error looking up transaction_id=%s' % txid)
        return r.json()

    def parse_tx(self, json_response):
        """
        Abstract method for parsing json response
        :param json_response: json returned by transaction connector
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

    def parse_tx(self, json_response):
        revoked = set()
        script = None
        for o in json_response['out']:
            if int(o.get('value', 1)) == 0:
                script = o['script'][4:]
            else:
                if o.get('spent'):
                    revoked.add(o.get('addr'))
        if not script:
            logging.error('transaction response is missing op_return script: %s', json_response)
            raise InvalidTransactionError('transaction response is missing op_return script' % json_response)
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

    def parse_tx(self, json_response):
        revoked = set()
        script = None
        for o in json_response['outputs']:
            if float(o.get('value', 1)) == 0:
                script = o['data_hex']
            else:
                if o.get('spent_by'):
                    revoked.add(o.get('addresses')[0])
        if not script:
            logging.error('transaction response is missing op_return script: %s', json_response)
            raise InvalidTransactionError('transaction response is missing op_return script' % json_response)
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
