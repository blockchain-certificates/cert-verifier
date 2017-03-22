"""
Verify blockchain certificates (http://www.blockcerts.org/)
"""

import requests
from cert_core import BlockcertVersion
from cert_core import model

from cert_verifier.checks import *
from cert_verifier.connectors import createTransactionLookupConnector

cache = SimpleCache()
lock = Lock()


class IssuerInfoV1x(object):
    def __init__(self, issuer_json):
        # TODO: need timerange from cert
        self.signing_key = issuer_json['issuerKeys'][0]['key']
        self.revocation_address = issuer_json['revocationKeys'][0]['key']


def get_issuer_info(issuer_url):
    r = requests.get(issuer_url)
    if r.status_code != 200:
        logging.error('Error looking up issuer keys at url=%s, status_code=%d', issuer_url, r.status_code)
    else:
        remote_json = r.json()
        logging.debug('Found issuer keys at url=%s', issuer_url)

        return IssuerInfoV1x(remote_json)
    return None


def create_v2_alpha_verification_steps(certificate_model, transaction_info, issuer_info):
    """
    :param certificate_model:
    :param transaction_info:
    :param issuer_info:
    """

    # TODO: ensure certificate was issued when key was valid

    # removing this check until we have caching for the schemas
    # try:
    #    schema_validator.validate_v1_2(certificate_json)
    #    logging.debug('The schema validates against v1.2 schema')
    # except Exception as e:
    #    logging.error('The certificate did not comply with the Blockchain Certificate schema', e)
    #    raise InvalidCertificateError('The certificate did not comply with the Blockchain Certificate schema', e)

    integrity_checker = VerificationGroup(
        steps=[IntegrityCheckerV2(certificate_model, transaction_info)],
        name='Checking certificate has not been tampered with')
    signature_checker = VerificationGroup(steps=[SignatureChecker(certificate_model, issuer_info)],
                                          name='Checking issuer signature')
    revocation_checker = VerificationGroup(steps=[RevocationChecker(certificate_model, transaction_info)],
                                           name='Checking not revoked by issuer')
    expiration_checker = VerificationGroup(steps=[ExpiredChecker(certificate_model)],
                                           name='Checking certificate has not expired')

    steps = [integrity_checker, signature_checker, revocation_checker, expiration_checker]
    all_steps = VerificationGroup(steps=steps, name='Validation')

    return all_steps


def create_v1_2_verification_steps(certificate_model, transaction_info, issuer_info):
    """
    :param certificate_model:
    :param transaction_info:
    :param issuer_info:
    """

    integrity_checker = VerificationGroup(
        steps=[IntegrityCheckerV1_2(certificate_model, transaction_info)],
        name='Checking certificate has not been tampered with')
    signature_checker = VerificationGroup(steps=[SignatureChecker(certificate_model, issuer_info)],
                                          name='Checking issuer signature')
    revocation_checker = VerificationGroup(steps=[RevocationChecker(certificate_model, transaction_info)],
                                           name='Checking not revoked')
    expiration_checker = VerificationGroup(steps=[ExpiredChecker(certificate_model)],
                                           name='Checking certificate has not expired')

    steps = [integrity_checker, signature_checker, revocation_checker, expiration_checker]
    all_steps = VerificationGroup(steps=steps, name='Validation')
    return all_steps


def create_v1_1_verification_steps(certificate_model, transaction_info, issuer_info):
    """
    0. Processing
    1. Compute SHA256 hash of local  Computing SHA256 digest of local certificate
    2. Fetch Bitcoin Transaction
    3. Compare hashes
    4. Check Media Lab signature
    5. Check not revoked
    :param certificate_model:
    :param transaction_info:
    :param issuer_info:
    :return:
    """

    integrity_checker = VerificationGroup(steps=[IntegrityCheckerV1_1(certificate_model, transaction_info)],
                                          name='Checking certificate has not been tampered with')
    signature_checker = VerificationGroup(steps=[SignatureChecker(certificate_model, issuer_info=issuer_info)],
                                          name='Checking issuer signature')
    revocation_checker = VerificationGroup(steps=[RevocationChecker(certificate_model, transaction_info)],
                                           name='Checking not revoked by issuer')

    steps = [integrity_checker, signature_checker, revocation_checker]
    all_steps = VerificationGroup(steps=steps, name='Validation')

    return all_steps


def verify_certificate(certificate_model):
    connector = createTransactionLookupConnector(certificate_model.chain)
    transaction_info = connector.lookup_tx(certificate_model.get_transaction_id())
    issuer_info = get_issuer_info(certificate_model.issuer_id)

    if certificate_model.version == BlockcertVersion.V1_1:
        verification_steps = create_v1_1_verification_steps(certificate_model, transaction_info, issuer_info)
    elif certificate_model.version == BlockcertVersion.V1_2:
        verification_steps = create_v1_2_verification_steps(certificate_model, transaction_info, issuer_info)
    elif certificate_model.version == BlockcertVersion.V2:
        verification_steps = create_v2_alpha_verification_steps(certificate_model, transaction_info, issuer_info)
    else:
        raise Exception('Unknown Blockchain Certificate version')

    verification_steps.execute()
    messages = []
    verification_steps.add_detailed_status(messages)
    for message in messages:
        print(message['name'] + ',' + str(message['status']))

    return messages


def verify_certificate_file(certificate_file_name, transaction_id=None):
    with open(certificate_file_name, 'rb') as cert_fp:
        certificate_bytes = cert_fp.read()
        certificate_json = json.loads(certificate_bytes.decode('utf-8'))
        certificate_model = model.to_certificate_model(certificate_json=certificate_json,
                                                       txid=transaction_id,
                                                       certificate_bytes=certificate_bytes)
        result = verify_certificate(certificate_model)
    return result


if __name__ == "__main__":
    result = verify_certificate_file('../tests/data/1.1/sample_signed_cert-1.1.json',
                                     '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
    print(result)

    result = verify_certificate_file('../tests/data/1.2/sample_signed_cert-1.2.json')
    print(result)

    # result = verify_cert_file('../tests/data/1.2/sample_signed_cert-1.2.json')
    # print(result)
    # result = verify_cert_file('../tests/data/1.1/sample_signed_cert-1.1.json',
    #                          '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
    # print(result)

    result = verify_certificate_file('../609c2989-275f-4f4c-ab02-b245cfb09017.json')
    print(result)
