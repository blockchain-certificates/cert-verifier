import json
import unittest

from cert_core import model

from cert_verifier import verifier, StepStatus


class TestVerify(unittest.TestCase):


    # end-to-end tests
    def test_verify_v1_2(self):
        result = verifier.verify_certificate_file('data/1.2/sample_signed_cert-1.2.json')
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])

    def test_verify_v1_1(self):
        result = verifier.verify_certificate_file('data/1.1/sample_signed_cert-1.1.json',
                                                  '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])

    def test_verify_cert_file_v1_2(self):
        result = verifier.verify_certificate_file('data/1.2/sample_signed_cert-1.2.json')
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])

    def test_verify_cert_file_v1_2_609(self):
        result = verifier.verify_certificate_file('data/1.2/609c2989-275f-4f4c-ab02-b245cfb09017.json')
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])

    def test_verify_cert_file_v1_2_b5d(self):
        result = verifier.verify_certificate_file('data/1.2/b5dee02e-50cd-4e48-ad33-de7d2eafa359.json')
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])

    def test_verify_cert_file_v1_1(self):
        result = verifier.verify_certificate_file('data/1.1/sample_signed_cert-1.1.json',
                                           '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])


if __name__ == '__main__':
    unittest.main()
