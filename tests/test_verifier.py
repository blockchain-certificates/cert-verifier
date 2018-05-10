import unittest

from cert_verifier import verifier, StepStatus

# Final result is last position in results array
VERIFICATION_RESULT_INDEX = -1
# second to last
AUTHENTICITY_RESULT_INDEX = -2
# revocation 3rd to last
REVOCATION_RESULT_INDEX = -3
# integrity is first check
INTEGRITY_RESULT_INDEX = 0

class TestVerify(unittest.TestCase):
    # end-to-end tests
    def test_verify_v1_2(self):
        result = verifier.verify_certificate_file('data/1.2/sample_signed_cert-1.2.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_v1_1(self):
        result = verifier.verify_certificate_file('data/1.1/sample_signed_cert-1.1.json',
                                                  '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v1_2(self):
        result = verifier.verify_certificate_file('data/1.2/sample_signed_cert-1.2.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v1_2_609(self):
        result = verifier.verify_certificate_file('data/1.2/609c2989-275f-4f4c-ab02-b245cfb09017.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v1_2_b5d(self):
        result = verifier.verify_certificate_file('data/1.2/b5dee02e-50cd-4e48-ad33-de7d2eafa359.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v1_1(self):
        result = verifier.verify_certificate_file('data/1.1/sample_signed_cert-1.1.json',
                                                  '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_alpha(self):
        result = verifier.verify_certificate_file('data/2.0-alpha/valid.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_alpha_with_v1_issuer(self):
        result = verifier.verify_certificate_file('data/2.0-alpha/valid_v2_certificate_with_v1_issuer.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_alpha_tampered(self):
        result = verifier.verify_certificate_file('data/2.0-alpha/invalid_tampered.json')
        self.assertEqual(StepStatus.failed.name, result[INTEGRITY_RESULT_INDEX]['status'])
        self.assertEqual(StepStatus.failed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_alpha_tampered_unmapped(self):
        result = verifier.verify_certificate_file('data/2.0-alpha/invalid_unmapped_fields.json')
        self.assertEqual(StepStatus.failed.name, result[INTEGRITY_RESULT_INDEX]['status'])
        self.assertEqual(StepStatus.failed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_alpha_revoked(self):
        result = verifier.verify_certificate_file('data/2.0-alpha/invalid_revoked.json')
        self.assertEqual(StepStatus.failed.name, result[REVOCATION_RESULT_INDEX]['status'])
        self.assertEqual(StepStatus.failed.name, result[VERIFICATION_RESULT_INDEX]['status'])
        print(result)

    def test_verify_cert_file_v2_authenticity_fail(self):
        result = verifier.verify_certificate_file('data/2.0-alpha/invalid_authenticity.json')
        self.assertEqual(StepStatus.failed.name, result[AUTHENTICITY_RESULT_INDEX]['status'])
        self.assertEqual(StepStatus.failed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_testnet(self):
        result = verifier.verify_certificate_file('data/2.0/testnet.json')
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_mocknet(self):
        result = verifier.verify_certificate_file('data/2.0/mocknet.json')
        self.assertEqual(StepStatus.mock_passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_regtest(self):
        result = verifier.verify_certificate_file('data/2.0/regtest.json')
        self.assertEqual(StepStatus.mock_passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_eth_ropsten(self):
        options = {'etherscan_api_token':'YRBJPTCAJEG8FH4WHR76BNFCN24DGHY8GV8'}
        result = verifier.verify_certificate_file('data/2.0/eth_ropsten.json', options=options)
        self.assertEqual(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

    def test_verify_cert_file_v2_eth_ropsten_no_api_token(self):
        result = verifier.verify_certificate_file('data/2.0/eth_ropsten.json')
        self.assertEquals(StepStatus.passed.name, result[VERIFICATION_RESULT_INDEX]['status'])

if __name__ == '__main__':
    unittest.main()
