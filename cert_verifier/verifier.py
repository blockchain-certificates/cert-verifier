"""
Verify blockchain certificates (http://www.blockcerts.org/)
"""

import requests
from cert_core import BlockcertVersion
from cert_core import model
from cert_core import parse_chain_from_address

from cert_verifier.checks import *
from cert_verifier.connectors import createTransactionLookupConnector


class IssuerInfoV1x(object):
    def __init__(self, issuer_json):
        self.signing_key = issuer_json['issuerKeys'][0]['key']
        self.revocation_address = issuer_json['revocationKeys'][0]['key']


class IssuerInfoV2(object):
    def __init__(self, signing_key, revoked_assertions):
        self.signing_key = signing_key
        self.revoked_assertions = revoked_assertions


def get_issuer_info(certificate_model):
    issuer_json = get_remote_json(certificate_model.issuer_id)
    if not issuer_json:
        raise Exception('Issuer URL returned no results ' + certificate_model.issuer_id)
    if certificate_model.version == BlockcertVersion.V2:
        revocation_url = certificate_model.certificate_json['badge']['issuer']['revocationList']
        revoked_json = get_remote_json(revocation_url)
        if revoked_json and revoked_json['revokedAssertions']:
            revoked_assertions = [RevokedAssertion(r['id'], r['revocationReason']) for r in
                                  revoked_json['revokedAssertions']]
        else:
            revoked_assertions = []
        return IssuerInfoV2(issuer_json['publicKey'], revoked_assertions)
    else:
        return IssuerInfoV1x(issuer_json)


class RevokedAssertion(object):
    def __init__(self, id, reason):
        self.id = id
        self.reason = reason


def get_remote_json(the_url):
    r = requests.get(the_url)
    if r.status_code != 200:
        logging.error('Error looking up url=%s, status_code=%d', the_url, r.status_code)
        return None
    else:
        remote_json = r.json()
        logging.debug('Found results at url=%s', the_url)
        return remote_json


def create_v2_verification_steps(certificate_model, transaction_info, issuer_info, chain):
    """
    :param certificate_model:
    :param transaction_info:
    :param issuer_info:
    :param chain:
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
        steps=[ReceiptIntegrityChecker(certificate_model, transaction_info),
               LocalHashIntegrityChecker(certificate_model, transaction_info),
               MerkleRootIntegrityChecker(certificate_model, transaction_info)],
        name='Checking certificate has not been tampered with')
    signature_checker = VerificationGroup(steps=[SignatureCheckerV2(certificate_model, issuer_info, chain)],
                                          name='Checking issuer signature')
    revocation_checker = VerificationGroup(steps=[RevocationCheckerV2(certificate_model, issuer_info)],
                                           name='Checking not revoked by issuer')
    expiration_checker = VerificationGroup(steps=[ExpiredChecker(certificate_model)],
                                           name='Checking certificate has not expired')

    steps = [integrity_checker, signature_checker, revocation_checker, expiration_checker]
    all_steps = VerificationGroup(steps=steps, name='Validation')

    return all_steps


def create_v1_2_verification_steps(certificate_model, transaction_info, issuer_info, chain):
    """
    :param certificate_model:
    :param transaction_info:
    :param issuer_info:
    :param chain:
    """

    integrity_checker = VerificationGroup(
        steps=[ReceiptIntegrityChecker(certificate_model, transaction_info),
               LocalHashIntegrityChecker(certificate_model, transaction_info),
               MerkleRootIntegrityChecker(certificate_model, transaction_info)],
        name='Checking certificate has not been tampered with')
    signature_checker = VerificationGroup(steps=[SignatureChecker(certificate_model, issuer_info, chain)],
                                          name='Checking issuer signature')
    revocation_checker = VerificationGroup(steps=[RevocationChecker(certificate_model, transaction_info)],
                                           name='Checking not revoked')
    expiration_checker = VerificationGroup(steps=[ExpiredChecker(certificate_model)],
                                           name='Checking certificate has not expired')

    steps = [integrity_checker, signature_checker, revocation_checker, expiration_checker]
    all_steps = VerificationGroup(steps=steps, name='Validation')
    return all_steps


def create_v1_1_verification_steps(certificate_model, transaction_info, issuer_info, chain):
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
    :param chain:
    :return:
    """

    integrity_checker = VerificationGroup(steps=[IntegrityCheckerV1_1(certificate_model, transaction_info)],
                                          name='Checking certificate has not been tampered with')
    signature_checker = VerificationGroup(steps=[SignatureChecker(certificate_model, issuer_info=issuer_info,
                                                                  chain=chain)],
                                          name='Checking issuer signature')
    revocation_checker = VerificationGroup(steps=[RevocationChecker(certificate_model, transaction_info)],
                                           name='Checking not revoked by issuer')

    steps = [integrity_checker, signature_checker, revocation_checker]
    all_steps = VerificationGroup(steps=steps, name='Validation')

    return all_steps


def verify_certificate(certificate_model):
    issuer_info = get_issuer_info(certificate_model)
    chain = parse_chain_from_address(issuer_info.signing_key)
    connector = createTransactionLookupConnector(chain)
    transaction_info = connector.lookup_tx(certificate_model.get_transaction_id())

    if certificate_model.version == BlockcertVersion.V1_1:
        verification_steps = create_v1_1_verification_steps(certificate_model, transaction_info, issuer_info, chain)
    elif certificate_model.version == BlockcertVersion.V1_2:
        verification_steps = create_v1_2_verification_steps(certificate_model, transaction_info, issuer_info, chain)
    elif certificate_model.version == BlockcertVersion.V2:
        verification_steps = create_v2_verification_steps(certificate_model, transaction_info, issuer_info, chain)
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
    # This one is revoked and should fail
    result = verify_certificate_file('../tests/data/2.0/93019408-acd8-4420-be5e-0400d643954a.json')
    print(result)
    # result = verify_certificate_file('../tests/data/1.1/sample_signed_cert-1.1.json',
    #                          '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
    # print(result)

    # result = verify_certificate_file('../tests/data/1.2/sample_signed_cert-1.2.json')
    # print(result)

    # result = verify_cert_file('../tests/data/1.2/sample_signed_cert-1.2.json')
    # print(result)
    # result = verify_cert_file('../tests/data/1.1/sample_signed_cert-1.1.json',
    #                          '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
    # print(result)
