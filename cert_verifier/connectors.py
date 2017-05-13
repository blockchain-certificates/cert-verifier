"""
Connectors supporting Bitcoin transaction lookups. This is used in the Blockchain Certificates project
(http://www.blockcerts.org/) for validating certificates on the blockchain.
"""
import logging

import requests
from cert_core import BlockcertVersion
from cert_core import Chain
from cert_core import PUBKEY_PREFIX
from cert_core.model import V2_REGEX

from cert_verifier import IssuerInfo, IssuerKey
from cert_verifier import TransactionData
from cert_verifier.errors import *


def createTransactionLookupConnector(chain=Chain.mainnet):
    """
    :param chain: which chain, supported values are testnet and mainnet
    :return: connector for looking up transactions
    """
    return FallbackConnector(chain)


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
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
        r = requests.get(self.url % txid, headers=headers)
        if r.status_code != 200:
            logging.error('Error looking up transaction_id with url=%s, status_code=%d', self.url % txid, r.status_code)
            raise InvalidTransactionError('error looking up transaction_id=%s' % txid)
        return r.json()

    def parse_tx(self, json_response):
        """
        Abstract method for parsing json response
        :param json_response: json returned by transaction connector
        :return: TransactionData
        """
        return None


class FallbackConnector(TransactionLookupConnector):
    def __init__(self, chain):
        self.chain = chain
        self.connectors = [BlockcypherConnector(chain), BlockrIOConnector(chain)]

    def lookup_tx(self, txid):
        exceptions = []
        for connector in self.connectors:
            try:
                response = connector.lookup_tx(txid)
                if response:
                    return response
            except Exception as e:
                logging.warning('Error looking up transaction, trying more connectors')
                exceptions.append(e)
        raise InvalidTransactionError(exceptions)


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
        signing_key = json_response['inputs'][0]['prev_out']['addr']
        for o in json_response['out']:
            if int(o.get('value', 1)) == 0:
                script = o['script'][4:]
            else:
                if o.get('spent'):
                    revoked.add(o.get('addr'))
        if not script:
            logging.error('transaction response is missing op_return script: %s', json_response)
            raise InvalidTransactionError('transaction response is missing op_return script' % json_response)
        return TransactionData(signing_key, script, None, revoked)


class BlockrIOConnector(TransactionLookupConnector):
    def __init__(self, chain):
        if chain == Chain.testnet:
            self.url = 'https://tbtc.blockr.io/api/v1/tx/info/%s'
        elif chain == Chain.mainnet:
            self.url = 'https://btc.blockr.io/api/v1/tx/info/%s'
        else:
            raise Exception(
                'unsupported chain (%s) requested with BlockrIO collector. Currently only testnet and mainnet are supported' % chain)

    def parse_tx(self, json_response):
        revoked = set()
        script = None
        time = json_response['data']['time_utc']
        signing_key = json_response['data']['vins'][0]['address']
        for o in json_response['data']['vouts']:
            if float(o.get('amount', 1)) == 0:
                if not 'extras' in o:
                    script = None
                else:
                    script = o['extras']['script'][4:]
            else:
                if o.get('is_spent') and float(o.get('is_spent', 1)) == 49:
                    revoked.add(o.get('address'))
        if not script:
            logging.error('transaction response is missing op_return script: %s', json_response)
            raise InvalidTransactionError('transaction response is missing op_return script')
        return TransactionData(signing_key, script, time, revoked)


class BlockcypherConnector(TransactionLookupConnector):
    """
    Lookup blockchain transactions using blockcypher api. Currently the 'mainnet' and 'testnet' chains are supported in
    this connector.
    """

    def __init__(self, chain):
        if chain == Chain.testnet:
            self.url = 'http://api.blockcypher.com/v1/btc/test3/txs/%s?limit=100'
        elif chain == Chain.mainnet:
            self.url = 'https://api.blockcypher.com/v1/btc/main/txs/%s?limit=100'
        else:
            raise Exception(
                'unsupported chain (%s) requested with blockcypher collector. Currently only testnet and mainnet are supported' % chain)

    def parse_tx(self, json_response):
        revoked = set()
        script = None
        time = json_response['received']
        signing_key = json_response['inputs'][0]['addresses'][0]
        for o in json_response['outputs']:
            if float(o.get('value', 1)) == 0:
                script = o['data_hex']
            else:
                if o.get('spent_by'):
                    revoked.add(o.get('addresses')[0])
        if not script:
            logging.error('transaction response is missing op_return script: %s', json_response)
            raise InvalidTransactionError('transaction response is missing op_return script' % json_response)
        return TransactionData(signing_key, script, time, revoked)


def get_remote_json(the_url):
    r = requests.get(the_url)
    if r.status_code != 200:
        logging.error('Error looking up url=%s, status_code=%d', the_url, r.status_code)
        return None
    else:
        remote_json = r.json()
        logging.debug('Found results at url=%s', the_url)
        return remote_json


def get_field_or_default(data, field_name):
    if field_name in data:
        return data[field_name]
    else:
        return None


def get_issuer_info(certificate_model):
    issuer_json = get_remote_json(certificate_model.issuer.id)
    if not issuer_json:
        raise Exception('Issuer URL returned no results ' + certificate_model.issuer_id)

    # we use the revocation list in the certificate
    revoked_assertions = []
    if certificate_model.version == BlockcertVersion.V2:
        if 'revocationList' in certificate_model.certificate_json['badge']['issuer']:
            revocation_url = certificate_model.certificate_json['badge']['issuer']['revocationList']
            revoked_json = get_remote_json(revocation_url)
            if revoked_json and revoked_json['revokedAssertions']:
                revoked_assertions = [V2_REGEX.search(r['id']).group(0) for r in revoked_json['revokedAssertions']]

    issuer_keys = []

    if '@context' in issuer_json:
        for public_key in issuer_json['publicKeys']:
            pk = public_key['publicKey'][len(PUBKEY_PREFIX):]

            created = get_field_or_default(public_key, 'created')
            expires = get_field_or_default(public_key, 'expires')
            revoked = get_field_or_default(public_key, 'revoked')
            issuer_keys.append(IssuerKey(pk, created, expires, revoked))
        return IssuerInfo(issuer_keys, revoked_assertions=revoked_assertions)
    else:
        # V1 issuer format
        issuer_key = IssuerKey(issuer_json['issuerKeys'][0]['key'])
        if revoked_assertions:
            # this is a v2 certificate with legacy issuer format
            return IssuerInfo([issuer_key], revoked_assertions=revoked_assertions)
        else:
            revocation_key = IssuerKey(issuer_json['revocationKeys'][0]['key'])
            issuer_info = IssuerInfo([issuer_key], revocation_keys=[revocation_key])
            return issuer_info
