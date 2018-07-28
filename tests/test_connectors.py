import json
import unittest

from mock import Mock

from cert_verifier.connectors import *


def mock_json():
    return {
        "out": [
            {
                "spent": False,
                "tx_index": 145158287,
                "type": 0,
                "addr": "1C1iqyXbk2rXVzGKyvs8HrFH79RMzTQQxA",
                "value": 2750,
                "n": 0,
                "script": "76a91478cc504569ea233a1fc9873aaefbedd03f40a30d88ac"
            },
            {
                "spent": False,
                "tx_index": 145158287,
                "type": 0,
                "addr": "14X6w2V5GGxwFui5EuK6cydWAji461LMre",
                "value": 2750,
                "n": 1,
                "script": "76a9142699cebbb24a29fda62de03b2faa14eac4b5f85c88ac"
            },
            {
                "spent": False,
                "tx_index": 145158287,
                "type": 0,
                "value": 0,
                "n": 2,
                "script": "6a20ddd7a9da081bf39bec8a049968010c0b429e969ea4b1b0f9badf9360d9d8886c"
            }
        ]
    }


def mock_transaction_lookup(transaction_id):
    m = Mock(status_code=200)
    m.json = mock_json
    return m


class TestConnectors(unittest.TestCase):
    def test_blockchain_info_parsing(self):
        with open('data/transaction_responses/blockchain_info.json') as trx_file:
            trx_json = json.load(trx_file)
            connector = BlockchainInfoConnector(chain=Chain.bitcoin_mainnet)
            data = connector.parse_tx(trx_json)
            self.assertEqual(data.op_return, '68f3ede17fdb67ffd4a5164b5687a71f9fbb68da803b803935720f2aa38f7728')
            self.assertEqual(0, len(data.revoked_addresses))

    def test_blockchain_info_parsing_revoked(self):
        with open('data/transaction_responses/blockchain_info_revoked.json') as trx_file:
            trx_json = json.load(trx_file)
            connector = BlockchainInfoConnector(chain=Chain.bitcoin_mainnet)
            data = connector.parse_tx(trx_json)
            self.assertEqual(data.op_return, '68f3ede17fdb67ffd4a5164b5687a71f9fbb68da803b803935720f2aa38f7728')
            self.assertEqual(1, len(data.revoked_addresses))
            self.assertTrue('1AAGG6jirbu9XwikFpkHokbbiYpjVtFe1G' in data.revoked_addresses)

    def test_blockcypher_parsing(self):
        with open('data/transaction_responses/blockcypher.json') as trx_file:
            trx_json = json.load(trx_file)
            connector = BlockcypherConnector(chain=Chain.bitcoin_mainnet)
            data = connector.parse_tx(trx_json)
            self.assertEqual(data.op_return, '68f3ede17fdb67ffd4a5164b5687a71f9fbb68da803b803935720f2aa38f7728')
            self.assertEqual(0, len(data.revoked_addresses))

    def test_blockcypher_parsing_revoked(self):
        with open('data/transaction_responses/blockcypher_revoked.json') as trx_file:
            trx_json = json.load(trx_file)
            connector = BlockcypherConnector(chain=Chain.bitcoin_mainnet)
            data = connector.parse_tx(trx_json)
            self.assertEqual(data.op_return, '68f3ede17fdb67ffd4a5164b5687a71f9fbb68da803b803935720f2aa38f7728')
            self.assertEqual(1, len(data.revoked_addresses))
            self.assertTrue('1AAGG6jirbu9XwikFpkHokbbiYpjVtFe1G' in data.revoked_addresses)

    def test_etherscan_parsing(self):
        with open('data/transaction_responses/etherscan_tx.json') as trx_file:
            trx_json = json.load(trx_file)
            connector = EtherscanConnector(chain=Chain.ethereum_ropsten, api_key='none')
            data = connector.parse_tx(trx_json)
            self.assertEqual(data.op_return, '0x8438d5be1cb1e8eed22dc510e0154cc896b644521b4dd3ad6f838b884af921ea')
            self.assertEqual('0xfc522b943d068116074c1c36839515fac0aa224e', data.signing_key)
