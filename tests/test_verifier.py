import unittest

from cert_verifier import verifier
import unittest
from mock import Mock
from cert_verifier.verifier import hexlify, unhexlify
import json

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


class TestVerify(unittest.TestCase):
    def test_compute_v1_hash(self):
        input_bytes = u'this is a certificate'.encode(encoding='utf-8')
        res = verifier.compute_v1_hash(input_bytes)
        self.assertEqual('ce0a928560e6bf808d56870ff1f2adf31deeafbfd42e17af52a92d0f02c6879a', res)


    #def test_get_hash_from_bc_op(self):
    #    script_input = b'eed3a6da081df36ded8a046668010d0d426e666ea4d1d0f6dadf6360d6d8886d'
    #    script = hexlify(script_input)
    #    tx_json = {u'out': [{u'addr': u'ADDR1', u'spent': False, u'value': 0, u'script': script}]}
    #    hashed_json = verify.get_hash_from_bc_op(tx_json=tx_json)
    #    self.assertEqual(hashed_json, script_input)

    #def test_get_hash_from_chain(self):
    #    script_input = b'eed3a6da081df36ded8a046668010d0d426e666ea4d1d0f6dadf6360d6d8886d'
    #    script = hexlify(script_input)
    #    tx_json = {'out': [{'spent': False, 'tx_index': 142155247, 'type': 0, 'value': 0, 'n': 2, 'script': script}]}
    #    hashed_json = verify.fetch_hash_from_chain(tx_json=tx_json)
    #    self.assertEqual(hashed_json,
    #                     '65656433613664613038316466333664656438613034363636383031306430643432366536363665613464316430663664616466363336306436643838383664')

    def test_compute_hash(self):
        hash_result = verifier.compute_v1_hash('abc123'.encode('utf-8'))
        self.assertEqual(hash_result, '6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090')

    #def test_check_revocation_not_revoked(self):
        # not_revoked = verify.check_revocation(tx_json={u'out': [{u'addr': u'ADDR1', u'spent': False}]},
        #                                  revoke_address='ADDR1')
        #self.assertEqual(not_revoked, True)

    #def test_check_revocation_is_spent(self):
    #    not_revoked = verify.check_revocation(tx_json={u'out': [{u'addr': u'ADDR1', u'spent': True}]},
    #                                     revoke_address='ADDR1')
    #    self.assertEqual(not_revoked, False)

    #def test_check_revocation_address_mismatch(self):
    #    not_revoked = verify.check_revocation(tx_json={u'out': [{u'addr': u'ADDR1', u'spent': False}]},
    #                                     revoke_address='ADDR2')
    #    self.assertEqual(not_revoked, False)

    #def test_check_revocation_multiple_txs_not_revoked(self):
    #    not_revoked = verify.check_revocation(tx_json={u'out': [{u'addr': u'ADDR1', u'spent': False},
    #                                                       {u'addr': u'ADDR2', u'spent': True}]},
    #                                     revoke_address='ADDR1')
    #    self.assertEqual(not_revoked, True)

    #def test_check_revocation_multiple_txs_revoked(self):
    #    not_revoked = verify.check_revocation(tx_json={u'out': [{u'addr': u'ADDR1', u'spent': False},
    #                                                       {u'addr': u'ADDR2', u'spent': True}]},
    #                                     revoke_address='ADDR2')
    #    self.assertEqual(not_revoked, False)

    # end-to-end tests
    def test_verify_v1_2(self):
        with open('../sample_data/1.2/sample_signed_cert-1.2.json') as cert_file:
            cert_json = json.load(cert_file)
            verifier.verify_v1_2(cert_json, 'testnet')
            self.assertTrue(True, 'this will not execute if test fails (will throw an exception)')

    def test_verify_v1_1(self):
        with open('../sample_data/1.1/sample_signed_cert-1.1.json', 'rb') as cert_file:
            result = verifier.verify_v1_1(cert_file.read(), '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa', 'testnet')
            self.assertEquals(result[-1][1], True)

    def test_verify_cert_file_v1_2(self):
        result = verifier.verify_cert_file('../sample_data/1.2/sample_signed_cert-1.2.json', 'testnet')
        self.assertTrue(True, 'this will not execute if test fails (will throw an exception)')

    def test_verify_cert_file_v1_1(self):
        result = verifier.verify_cert_file('../sample_data/1.1/sample_signed_cert-1.1.json', '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa', 'testnet')
        self.assertEquals(result[-1][1], True)


if __name__ == '__main__':
    unittest.main()
