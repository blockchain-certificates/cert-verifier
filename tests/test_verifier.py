import unittest

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

    def test_verify_cert_file_v2(self):
        result = verifier.verify_certificate_file('data/2.0/ee098d8e-c8c1-4ff0-b38a-8d868f1daa8e.json')
        print(result)
        self.assertEquals(StepStatus.passed.name, result[-1]['status'])

    def test_verify_cert_file_v2_revoked(self):
        # 93019408-acd8-4420-be5e-0400d643954a
        # 1dabb524-8365-4550-b499-a8119f6bf5d2
        result = verifier.verify_certificate_file('data/2.0/d4d08ae3-6d8c-489d-be60-cbffc783f43f.json')
        print(result)
        self.assertEquals(StepStatus.failed.name, result[2]['status'])


if __name__ == '__main__':
    unittest.main()
