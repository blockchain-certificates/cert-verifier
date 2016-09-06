import unittest

from cert_verifier import verify


class TestVerify(unittest.TestCase):
    def test_compute_v1_hash(self):
        input_bytes = u'this is a certificate'.encode(encoding='utf-8')
        res = verify.compute_v1_hash(input_bytes)
        self.assertEqual('ce0a928560e6bf808d56870ff1f2adf31deeafbfd42e17af52a92d0f02c6879a', res)




if __name__ == '__main__':
    unittest.main()
