"""
Verify blockchain certificates (http://www.blockcerts.org/)
"""
import hashlib
import json
import logging

import bitcoin
import requests
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
from cert_schema.schema_tools import schema_validator
from merkleproof import utils
from merkleproof.MerkleTree import sha256
from pyld import jsonld

from cert_verifier import parse_chain_from_address, StepStatus
from cert_verifier.connectors import BlockcypherConnector, createTransactionLookupConnector
from cert_verifier.errors import *


def hashes_match(actual_hash, expected_hash):
    return actual_hash in expected_hash or actual_hash == expected_hash


class ProcessingState:
    def __init__(self):
        self.certificate_json = None
        self.transaction_id = None
        self.local_hash = None
        self.blockchain_hash = None


class ProcessingStateV1(ProcessingState):
    def __init__(self, certificate_bytes, transaction_id):
        self.certificate_bytes = certificate_bytes
        self.transaction_id = transaction_id
        cert_utf8 = certificate_bytes.decode('utf-8')
        self.certificate_json = json.loads(cert_utf8)


class ProcessingStateV2(ProcessingState):
    def __init__(self, certificate_json):
        self.certificate_json = certificate_json


class ValidationStep(object):
    """Individual task involved in validation"""

    def execute(self, state):
        passed = False
        try:
            passed = self.do_execute(state)
            if passed:
                logging.debug('Validation step %s passed', self.__class__.__name__)
            else:
                logging.error('Validation step %s failed!', self.__class__.__name__)
            return passed
        except Exception:
            logging.exception('caught exception executing step %s', self.__class__.__name__)
        return passed

    def do_execute(self, state):
        """Steps should override this"""
        return False


class ValidationGroup(ValidationStep):
    """
    Wraps steps in a phase of validation. Generally you should be able to instantiate this directly instead of subclass
    """

    def __init__(self, steps, name, success_status=StepStatus.passed):
        self.steps = steps
        self.name = name
        self.success_status = success_status
        self.status = StepStatus.not_started

    def name(self):
        return self.name

    def do_execute(self, state):
        for step in self.steps:
            passed = step.execute(state)
            if passed:
                self.status = self.success_status
            else:
                self.status = StepStatus.failed
                break
        return self.status == StepStatus.done or self.status == StepStatus.passed

    def add_detailed_status(self, messages):
        # first add any child detailed results
        for step in self.steps:
            if isinstance(step, ValidationGroup):
                step.add_detailed_status(messages)

        # add own results
        my_results = {'name': self.name, 'status': self.status.name}
        messages.append(my_results)


class ComputeHashV1(ValidationStep):
    def do_execute(self, state):
        state.local_hash = hashlib.sha256(state.certificate_bytes).hexdigest()
        return True


class FetchTransaction(ValidationStep):
    def __init__(self, connector):
        self.connector = connector

    def do_execute(self, state):
        transaction_info = self.connector.lookup_tx(state.transaction_id)
        if transaction_info:
            state.blockchain_hash = transaction_info.script
            state.revoked_addresses = transaction_info.revoked_addresses
            return True
        return False


class CompareHashesV1(ValidationStep):
    def do_execute(self, state):
        result = hashes_match(state.local_hash, state.blockchain_hash)
        return result


class FetchIssuerKeys(ValidationStep):
    def do_execute(self, state):
        signer_url = state.certificate_json['certificate']['issuer']['id']

        r = requests.get(signer_url)
        remote_json = None
        if r.status_code != 200:
            logging.error('Error looking up issuer keys at url=%s, status_code=%d', signer_url, r.status_code)
        else:
            remote_json = r.json()
            logging.info('Found issuer keys at url=%s', signer_url)

        if remote_json:
            state.signing_key = remote_json['issuerKeys'][0]['key']
            state.revocation_address = remote_json['revocationKeys'][0]['key']
            return True
        return False


class CheckIssuerSignature(ValidationStep):
    def do_execute(self, state):
        uid = state.certificate_json['assertion']['uid']
        signature = state.certificate_json['signature']
        if state.signing_key is None or uid is None or signature is None:
            return False
        message = BitcoinMessage(uid)
        return VerifyMessage(state.signing_key, message, signature)


class CheckNotRevoked(ValidationStep):
    def do_execute(self, state):
        revoked = state.revocation_address in state.revoked_addresses
        return not revoked


class ComputeHashV2(ValidationStep):
    def do_execute(self, state):
        normalized = jsonld.normalize(state.certificate_json['document'],
                                      {'algorithm': 'URDNA2015', 'format': 'application/nquads'})
        hashed = sha256(normalized)
        state.local_hash = hashed
        return True


class ValidateReceipt(ValidationStep):
    def do_execute(self, state):
        receipt = state.certificate_json['receipt']
        return utils.validate_receipt(receipt)


class LookupTransactionId(ValidationStep):
    def do_execute(self, state):
        state.transaction_id = state.certificate_json['receipt']['anchors'][0]['sourceId']
        return True


class CompareHashesV2(ValidationStep):
    def do_execute(self, state):
        expected_certificate_hash = state.certificate_json['receipt']['targetHash']
        merkle_root = state.certificate_json['receipt']['merkleRoot']

        cert_hashes_match = hashes_match(state.local_hash, expected_certificate_hash)
        merkle_root_matches = hashes_match(state.blockchain_hash, merkle_root)
        return cert_hashes_match and merkle_root_matches


def verify_v1_2(certificate_json):
    state = ProcessingStateV2(certificate_json)

    chain = parse_chain_from_address(certificate_json['document']['recipient']['pubkey'])
    connector = createTransactionLookupConnector(chain)
    bitcoin.SelectParams(chain.name)

    validate_receipt = ValidationGroup(steps=[ValidateReceipt()], name='Validate receipt')
    compute_hash = ValidationGroup(steps=[ComputeHashV2()], name='Computing SHA256 digest of local certificate',
                                   success_status=StepStatus.done)
    fetch_transaction = ValidationGroup(steps=[LookupTransactionId(), FetchTransaction(connector)],
                                        name='Fetch Bitcoin Transaction', success_status=StepStatus.done)
    compare_certificate_hash = ValidationGroup(steps=[CompareHashesV2()], name='Comparing local and merkle hashes')
    check_signature = ValidationGroup(steps=[FetchIssuerKeys(), CheckIssuerSignature()], name='Checking issuer signature')
    check_revoked = ValidationGroup(steps=[CheckNotRevoked()], name='Checking not revoked by issuer')

    steps = [validate_receipt, compute_hash, fetch_transaction, compare_certificate_hash,
             check_signature, check_revoked]
    all_steps = ValidationGroup(steps=steps, name='Validation')

    # first ensure this is a valid v1.2 cert.
    try:
        schema_validator.validate_v1_2(certificate_json)
        logging.debug('schema validates against v1.2 schema')
    except Exception as e:
        logging.error('Schema validation failed', e)
        raise InvalidCertificateError('Schema validation failed', e)

    result = all_steps.execute(state)
    messages = []
    all_steps.add_detailed_status(messages)
    for message in messages:
        print(message['name'] + ',' + str(message['status']))

    return messages


def verify_v1_1(cert_file_bytes, transaction_id):
    """
    0. Processing
    1. Compute SHA256 hash of local  Computing SHA256 digest of local certificate
    2. Fetch Bitcoin Transaction
    3. Compare hashes
    4. Check Media Lab signature
    5. Check not revoked
    :param cert_file_bytes:
    :param transaction_id:
    :return:
    """
    state = ProcessingStateV1(cert_file_bytes, transaction_id)

    chain = parse_chain_from_address(state.certificate_json['recipient']['pubkey'])
    connector = BlockcypherConnector(chain)
    bitcoin.SelectParams(chain.name)

    compute_hash = ValidationGroup(steps=[ComputeHashV1()], name='Computing SHA256 digest of local certificate',
                                   success_status=StepStatus.done)
    fetch_transaction = ValidationGroup(steps=[FetchTransaction(connector)], name='Fetch Bitcoin Transaction',
                                        success_status=StepStatus.done)
    compare_hash = ValidationGroup(steps=[CompareHashesV1()], name='Comparing local and blockchain hashes')
    check_signature = ValidationGroup(steps=[FetchIssuerKeys(), CheckIssuerSignature()], name='Checking issuer signature')
    check_revoked = ValidationGroup(steps=[CheckNotRevoked()], name='Checking not revoked by issuer')

    steps = [compute_hash, fetch_transaction, compare_hash, check_signature, check_revoked]
    all_steps = ValidationGroup(steps=steps, name='Validation')

    result = all_steps.execute(state)
    messages = []
    all_steps.add_detailed_status(messages)
    for message in messages:
        print(message['name'] + ',' + str(message['status']))

    return messages


def verify_cert_file(cert_file, transaction_id=None):
    with open(cert_file, 'rb') as cert_fp:
        contents = cert_fp.read()
        result = verify_cert_contents(contents, transaction_id)
    return result


def verify_cert_contents(cert_bytes, transaction_id=None):
    cert_utf8 = cert_bytes.decode('utf-8')
    cert_json = json.loads(cert_utf8)
    if '@context' in cert_json:
        result = verify_v1_2(cert_json)
    else:
        if transaction_id is None:
            raise Exception('v1 certificate is not accompanied with a transaction id')
        result = verify_v1_1(cert_bytes, transaction_id)
    return result


if __name__ == "__main__":
    with open('../sample_data/1.1/sample_signed_cert-1.1.json', 'rb') as cert_file:
        result = verify_v1_1(cert_file.read(), '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
        print(result)

    with open('../sample_data/1.2/sample_signed_cert-1.2.json') as cert_file:
        cert_json = json.load(cert_file)
        result = verify_v1_2(cert_json)
        print(result)

    result = verify_cert_file('../sample_data/1.2/sample_signed_cert-1.2.json')
    print(result)
    result = verify_cert_file('../sample_data/1.1/sample_signed_cert-1.1.json',
                              '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa')
    print(result)
