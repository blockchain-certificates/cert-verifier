import unittest

from cert_core import to_certificate_model
from mock import Mock

from cert_verifier.checks import *


class TestVerify(unittest.TestCase):

    def test_compare_hashes_v1_1(self):
        content_to_verify = '{"abc123": true}'.encode('utf-8')
        mock_transaction = Mock()
        mock_transaction.op_return = 'e323ace018d459e737988f8c02944224f9d02d2ee58c60eaaf134dd2a36e7d32'

        checker = BinaryFileIntegrityChecker(content_to_verify, mock_transaction)
        self.assertTrue(checker.do_execute())

    def test_compare_hashes_v1_1_fail(self):
        content_to_verify = '{"abc123": true}'.encode('utf-8')
        mock_transaction = Mock()
        mock_transaction.op_return = 'e323ace7777459e737988f8c02944224f9d02d2ee58c60eaaf134dd2a36e7d32'

        checker = BinaryFileIntegrityChecker(content_to_verify, mock_transaction)
        self.assertEqual(False, checker.do_execute())

    def test_expired(self):
        expires = pytz.UTC.localize(datetime(2007, 12, 5))
        checker = ExpiredChecker(expires)
        self.assertEqual(False, checker.do_execute())

    def test_not_expired(self):
        now = datetime.utcnow()
        next_year = now.replace(year=now.year + 1)
        expires = pytz.UTC.localize(next_year)
        checker = ExpiredChecker(expires)
        self.assertTrue(checker.do_execute())

    def test_no_expiration(self):
        expires = None
        checker = ExpiredChecker(expires)
        self.assertTrue(checker.do_execute())

    def test_check_not_revoked_fail(self):
        revoked_addresses = set()
        revoked_addresses.add('123456')
        revoked_addresses.add('444444')

        addresses_to_check = ['123456']
        revoked_checker = RevocationChecker(addresses_to_check, revoked_addresses)
        result = revoked_checker.do_execute()
        self.assertFalse(result)

    def test_check_not_revoked_pass(self):
        revoked_addresses = set()
        revoked_addresses.add('343434')
        revoked_addresses.add('444444')

        addresses_to_check = ['123456']
        revoked_checker = RevocationChecker(addresses_to_check, revoked_addresses)
        result = revoked_checker.do_execute()
        self.assertTrue(result)

    def test_verify_expired(self):
        with open('data/1.2/expired.json') as cert_file:
            cert_json = json.load(cert_file)
            certificate_model = to_certificate_model(certificate_json=cert_json)
        not_expired_checker = ExpiredChecker(certificate_model.expires)
        self.assertFalse(not_expired_checker.do_execute())

    def test_not_yet_expired(self):
        with open('data/1.2/not_yet_expired.json') as cert_file:
            cert_json = json.load(cert_file)
            certificate_model = to_certificate_model(certificate_json=cert_json)
        not_expired_checker = ExpiredChecker(certificate_model.expires)
        self.assertTrue(not_expired_checker.do_execute())


if __name__ == '__main__':
    unittest.main()
