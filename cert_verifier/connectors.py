"""
Connectors supporting Bitcoin transaction lookups. This is used in the Blockchain Certificates project
(http://www.blockcerts.org/) for validating certificates on the blockchain.
"""
import logging

import requests
from cert_core import BlockchainType, BlockcertVersion, Chain
from cert_core import PUBKEY_PREFIX

from cert_verifier import IssuerInfo, IssuerKey
from cert_verifier import TransactionData
from cert_verifier.errors import *


def createTransactionLookupConnector(chain=Chain.bitcoin_mainnet, options=None):
    """
    :param chain: which chain, supported values are testnet and mainnet
    :return: connector for looking up transactions
    """
    if chain == Chain.mockchain or chain == Chain.bitcoin_regtest:
        return MockConnector(chain)
    elif chain.blockchain_type == BlockchainType.ethereum:
        if options and 'etherscan_api_token' in options:
            etherscan_api_token = options['etherscan_api_token']
        else:
            etherscan_api_token = None
        return EtherscanConnector(chain, etherscan_api_token)
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


class MockConnector(TransactionLookupConnector):
    def __init__(self, chain):
        self.chain = chain

    def lookup_tx(self, txid):
        return True

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

    def __init__(self, chain=Chain.bitcoin_mainnet):
        if chain != Chain.bitcoin_mainnet:
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
        if chain == Chain.bitcoin_testnet:
            self.url = 'https://tbtc.blockr.io/api/v1/tx/info/%s'
        elif chain == Chain.bitcoin_mainnet:
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
        if chain == Chain.bitcoin_testnet:
            self.url = 'http://api.blockcypher.com/v1/btc/test3/txs/%s?limit=100'
        elif chain == Chain.bitcoin_mainnet:
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
"""
{
   "jsonrpc":"2.0",
   "result":{
      "blockHash":"0x2902c15778590321b5a14fc574105bb54d1a411e981e476c8ffa8af84ed55189",
      "blockNumber":"0x1b6b73",
      "condition":null,
      "creates":null,
      "from":"0xfc522b943d068116074c1c36839515fac0aa224e",
      "gas":"0x61a8",
      "gasPrice":"0x4a817c800",
      "hash":"0xd7f7ccdb8de0ece57136696020af60026428234769263eb6ae882b8b7f3a1c96",
      "input":"0x8438d5be1cb1e8eed22dc510e0154cc896b644521b4dd3ad6f838b884af921ea",
      "networkId":3,
      "nonce":"0x1",
      "publicKey":"0x85fa3aea18d891f716642d6caf772c9cfa38047d578014b96d980cbc1b44e40988a46f72e0765a68d25c7931d2bbe5552278290d32c4612dd5aa6eca8fbadc57",
      "r":"0x4d9258cb8b4af065049ea2521a4032d617909104b2bb22d7349734c0a56296cb",
      "raw":"0xf884018504a817c8008261a894deaddeaddeaddeaddeaddeaddeaddeaddeaddead80a08438d5be1cb1e8eed22dc510e0154cc896b644521b4dd3ad6f838b884af921ea29a04d9258cb8b4af065049ea2521a4032d617909104b2bb22d7349734c0a56296cba02ff68fcac79343fcee6eee5303cfa8e98e2b89e9f68a9c920425d40f47493b09",
      "s":"0x2ff68fcac79343fcee6eee5303cfa8e98e2b89e9f68a9c920425d40f47493b09",
      "standardV":"0x0",
      "to":"0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
      "transactionIndex":"0x3",
      "v":"0x29",
      "value":"0x0"
   },
   "id":1
}
"""
class EtherscanConnector(TransactionLookupConnector):

    def __init__(self, chain, api_key):
        if chain == Chain.ethereum_mainnet:
            url_prefix = 'https://api.etherscan.io'
        elif chain == Chain.ethereum_ropsten:
            url_prefix = 'https://ropsten.etherscan.io'
        else:
            raise Exception(
                'unsupported chain (%s) requested with Etherscan collector. Currently only mainnet and ropsten are supported' % chain)

        self.url = url_prefix + '/api?module=proxy&action=eth_getTransactionByHash&apikey=' + api_key + '&txhash=%s'

    def parse_tx(self, json_response):
        # TODO: need time_utc, which we can get from another API
        #time = json_response['data']['time_utc']
        signing_key = json_response['result']['from']
        script = json_response['result']['input']

        if not script:
            logging.error('transaction response is missing input: %s', json_response)
            raise InvalidTransactionError('transaction response is missing input')
        return TransactionData(signing_key, script, date_time_utc=None, revoked_addresses=None)


def get_field_or_default(data, field_name):
    if field_name in data:
        return data[field_name]
    else:
        return None


def get_issuer_info(certificate_model):
    issuer_json = get_remote_json(certificate_model.issuer.id)
    if not issuer_json:
        raise Exception('Issuer URL returned no results ' + certificate_model.issuer.id)

    # we use the revocation list in the certificate
    revoked_assertions = []
    v2ish = certificate_model.version == BlockcertVersion.V2 or certificate_model.version == BlockcertVersion.V2_ALPHA
    if v2ish:
        if 'revocationList' in certificate_model.certificate_json['badge']['issuer']:
            revocation_url = certificate_model.certificate_json['badge']['issuer']['revocationList']
            revoked_json = get_remote_json(revocation_url)
            if revoked_json and revoked_json['revokedAssertions']:
                revoked_assertions = [r['id'] for r in revoked_json['revokedAssertions']]

    issuer_keys = []

    if '@context' in issuer_json:
        if 'publicKey' in issuer_json:
            for public_key in issuer_json['publicKey']:
                pk = public_key['id'][len(PUBKEY_PREFIX):]
                created = get_field_or_default(public_key, 'created')
                expires = get_field_or_default(public_key, 'expires')
                revoked = get_field_or_default(public_key, 'revoked')
                issuer_keys.append(IssuerKey(pk, created, expires, revoked))
        # Backcompat for v2 alpha issuer
        elif 'publicKeys' in issuer_json:
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
