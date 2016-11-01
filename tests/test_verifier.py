import json
import unittest

from cert_verifier import verifier
from cert_verifier.verifier import StepStatus, ComputeHashV1, ProcessingState, ProcessingStateV1, CheckNotRevoked, \
    ProcessingStateV2, CheckNotExpired


class TestVerify(unittest.TestCase):
    def test_compute_hash(self):
        hashv1 = ComputeHashV1()
        state = ProcessingStateV1('{"abc123": true}'.encode('utf-8'), 'unused_txid')
        hashv1.do_execute(state)
        self.assertEquals('e323ace018d459e737988f8c02944224f9d02d2ee58c60eaaf134dd2a36e7d32', state.local_hash)

    def test_check_not_revoked_fail(self):
        state = ProcessingState()
        state.revocation_address = '123456'

        revoked_addresses = set()
        revoked_addresses.add('123456')
        revoked_addresses.add('444444')
        state.revoked_addresses = revoked_addresses

        revoked_checker = CheckNotRevoked()
        result = revoked_checker.execute(state)
        self.assertFalse(result)

    def test_check_not_revoked_pass(self):
        state = ProcessingState()
        state.revocation_address = '123456'

        revoked_addresses = set()
        revoked_addresses.add('343434')
        revoked_addresses.add('444444')
        state.revoked_addresses = revoked_addresses

        revoked_checker = CheckNotRevoked()
        result = revoked_checker.execute(state)
        self.assertTrue(result)

    # end-to-end tests
    def test_verify_v1_2(self):
        with open('data/1.2/sample_signed_cert-1.2.json') as cert_file:
            cert_json = json.load(cert_file)
            result = verifier.verify_v1_2(cert_json)
            self.assertEquals(result[-1]['status'], StepStatus.passed.name)

    def test_verify_v1_1(self):
        with open('data/1.1/sample_signed_cert-1.1.json', 'rb') as cert_file:
            result = verifier.verify_v1_1(cert_file.read(),
                                          '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
            self.assertEquals(result[-1]['status'], StepStatus.passed.name)

    def test_verify_cert_file_v1_2(self):
        result = verifier.verify_cert_file('data/1.2/sample_signed_cert-1.2.json')
        self.assertEquals(result[-1]['status'], StepStatus.passed.name)

    def test_verify_cert_file_v1_2_609(self):
        result = verifier.verify_cert_file('data/1.2/609c2989-275f-4f4c-ab02-b245cfb09017.json')
        self.assertEquals(result[-1]['status'], StepStatus.passed.name)

    def test_verify_cert_file_v1_2_b5d(self):
        result = verifier.verify_cert_file('data/1.2/b5dee02e-50cd-4e48-ad33-de7d2eafa359.json')
        self.assertEquals(result[-1]['status'], StepStatus.passed.name)

    def test_verify_expired(self):
        with open('data/1.2/expired.json') as cert_file:
            cert_json = json.load(cert_file)
        processing_state = ProcessingStateV2(cert_json['document'], None)
        not_expired_checker = CheckNotExpired()
        self.assertFalse(not_expired_checker.do_execute(processing_state))

    def test_not_yet_expired(self):
        with open('data/1.2/not_yet_expired.json') as cert_file:
            cert_json = json.load(cert_file)
        processing_state = ProcessingStateV2(cert_json['document'], None)
        not_expired_checker = CheckNotExpired()
        self.assertTrue(not_expired_checker.do_execute(processing_state))

    def test_verify_cert_file_v1_1(self):
        result = verifier.verify_cert_file('data/1.1/sample_signed_cert-1.1.json',
                                           '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
        self.assertEquals(result[-1]['status'], StepStatus.passed.name)


if __name__ == '__main__':
    unittest.main()
