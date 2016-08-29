import requests
import logging

class BlockchainInfoConnector:
    def __init__(self, chain):
        if chain != 'mainnet':
            raise Exception('only mainnet chain is supported with blockchain.info collector')
        self.url = 'https://blockchain.info/rawtx/%s?cors=true'

    def lookup_tx(self, txid):
        r = requests.get(self.url % txid)
        if r.status_code != 200:
            logging.error('Error looking up by transaction_id=%s, status_code=%d', txid, r.status_code)
            return None
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
                raise Exception('transaction is missing op_return')
            return TransactionData(revoked, script)


class BlockcypherConnector:
    def __init__(self, chain):
        if chain != 'testnet':
            raise Exception('only testnet chain is supported with blockcypher collector')
        self.url = 'http://api.blockcypher.com/v1/btc/test3/txs/%s'


    def lookup_tx(self, txid):
        r = requests.get(self.url % txid)
        if r.status_code != 200:
            logging.error('Error looking up by transaction_id=%s, status_code=%d', txid, r.status_code)
            return None
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
                raise Exception('transaction is missing op_return')
            return TransactionData(revoked, script)


class TransactionData:
    def __init__(self, revoked_addresses, script):
        self.revoked_addresses = revoked_addresses
        self.script = script