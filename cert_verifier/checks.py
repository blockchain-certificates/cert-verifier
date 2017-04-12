import hashlib
import json
import logging
from datetime import datetime
from threading import Lock

import bitcoin
import pytz
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
from cert_core import Chain
from chainpoint.chainpoint import Chainpoint
from ld_koblitz_signatures import signatures
from ld_koblitz_signatures.document_loader import jsonld_document_loader
from ld_koblitz_signatures.signatures import SignatureOptions
from werkzeug.contrib.cache import SimpleCache

from cert_verifier import StepStatus

cache = SimpleCache()
lock = Lock()


def cached_document_loader(url, override_cache=False):
    if not override_cache:
        result = cache.get(url)
        if result:
            return result
    doc = jsonld_document_loader(url)
    cache.set(url, doc)
    return doc


JSONLD_OPTIONS = {'algorithm': 'URDNA2015', 'format': 'application/nquads', 'documentLoader': cached_document_loader}


def cached_document_loader(url, override_cache=False):
    if not override_cache:
        result = cache.get(url)
        if result:
            return result
    doc = jsonld_document_loader(url)
    cache.set(url, doc)
    return doc


class VerificationCheck(object):
    """Individual task involved in verification"""

    def __init__(self, certificate, transaction_info=None, issuer_info=None):
        self.certificate = certificate
        self.transaction_info = transaction_info
        self.issuer_info = issuer_info

    def execute(self):
        return self.do_execute()

    def do_execute(self):
        """Steps should override this"""
        return False


class VerificationGroup(VerificationCheck):
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

    def do_execute(self):

        for step in self.steps:
            try:
                passed = step.do_execute()
                if passed:
                    self.status = self.success_status
                    logging.debug('Verification step %s passed', self.__class__.__name__)
                else:
                    self.status = StepStatus.failed
                    logging.error('Verification step %s failed!', self.__class__.__name__)
                    break
            except Exception:
                logging.exception('caught exception executing step %s', self.__class__.__name__)
                self.status = StepStatus.failed
                break
        return self.status == StepStatus.done or self.status == StepStatus.passed

    def add_detailed_status(self, messages):
        # first add any child detailed results
        for step in self.steps:
            if isinstance(step, VerificationGroup):
                step.add_detailed_status(messages)

        # add own results
        my_results = {'name': self.name, 'status': self.status.name}
        messages.append(my_results)


class IntegrityCheckerV1_1(VerificationCheck):
    def __init__(self, certificate, transaction_info):
        super(IntegrityCheckerV1_1, self).__init__(certificate, transaction_info=transaction_info)

    def do_execute(self):
        blockchain_hash = self.transaction_info.op_return
        local_hash = hashlib.sha256(self.certificate.document).hexdigest()
        return hashes_match(blockchain_hash, local_hash)


class LocalHashIntegrityChecker(VerificationCheck):
    def __init__(self, certificate, transaction_info):
        super(LocalHashIntegrityChecker, self).__init__(certificate, transaction_info=transaction_info)

    def do_execute(self):
        normalized = signatures.normalize_jsonld(self.certificate.document)
        local_hash = hash_normalized(normalized)
        cert_hashes_match = hashes_match(local_hash, self.certificate.blockcert_signature.merkle_proof.target_hash)
        return cert_hashes_match


class MerkleRootIntegrityChecker(VerificationCheck):
    def __init__(self, certificate, transaction_info):
        super(MerkleRootIntegrityChecker, self).__init__(certificate, transaction_info=transaction_info)

    def do_execute(self):
        merkle_root_matches = hashes_match(self.transaction_info.op_return,
                                           self.certificate.blockcert_signature.merkle_proof.merkle_root)
        return merkle_root_matches


class ReceiptIntegrityChecker(VerificationCheck):
    def __init__(self, certificate, transaction_info):
        super(ReceiptIntegrityChecker, self).__init__(certificate, transaction_info=transaction_info)

    def do_execute(self):
        cp = Chainpoint()
        valid_receipt = cp.valid_receipt(json.dumps(self.certificate.blockcert_signature.merkle_proof.proof_json))
        return valid_receipt


class RevocationChecker(VerificationCheck):
    def __init__(self, certificate, transaction_info):
        super(RevocationChecker, self).__init__(certificate, transaction_info=transaction_info)

    def do_execute(self):
        spend_to_revoke_blockcert_signature = self.certificate.blockcert_signature
        if spend_to_revoke_blockcert_signature.recipient_public_key and \
                        spend_to_revoke_blockcert_signature.recipient_public_key in self.transaction_info.revoked_addresses:
            return False
        if spend_to_revoke_blockcert_signature.per_recipient_revocation_key and \
                        spend_to_revoke_blockcert_signature.per_recipient_revocation_key in self.transaction_info.revoked_addresses:
            return False
        return True


class RevocationCheckerV2(VerificationCheck):
    def __init__(self, certificate, issuer_info):
        super(RevocationCheckerV2, self).__init__(certificate, issuer_info=issuer_info)

    def do_execute(self):
        uids_to_check = [r.id for r in self.issuer_info.revoked_assertions]
        result = not self.certificate.uid in uids_to_check
        if not result:
            logging.error('This certificate has been revoked by the issuer')
        return result

class ExpiredChecker(VerificationCheck):
    def __init__(self, certificate):
        super(ExpiredChecker, self).__init__(certificate)

    def do_execute(self):
        return check_not_expired(self.certificate.expires)


class SignatureChecker(VerificationCheck):
    def __init__(self, certificate, issuer_info, chain=Chain.mainnet):
        super(SignatureChecker, self).__init__(certificate, issuer_info=issuer_info)
        self.chain = chain

    def do_execute(self):
        return check_signature(self.issuer_info.signing_key, self.certificate.uid,
                               self.certificate.blockcert_signature.signature_value, self.chain)


class SignatureCheckerV2(VerificationCheck):
    def __init__(self, certificate, issuer_info, chain=Chain.mainnet):
        super(SignatureCheckerV2, self).__init__(certificate, issuer_info=issuer_info)
        self.chain = chain

    def do_execute(self):
        # import copy
        # certificate_json_copy = copy.deepcopy(self.certificate.certificate_json)
        # del certificate_json_copy['signature']
        # normalized = jsonld.normalize(certificate_json_copy, options=JSONLD_OPTIONS)

        # return check_signature(self.issuer_info.signing_key, normalized,
        #                       self.certificate.blockcert_signature.signature_value, self.chain)
        signed_json = self.certificate.certificate_json
        options = SignatureOptions(signed_json['signature']['created'], signed_json['signature']['creator'])
        return signatures.verify(signed_json, options, self.chain.name)


def hash_normalized(normalized):
    encoded = normalized.encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def hashes_match(actual_hash, expected_hash):
    return actual_hash in expected_hash or actual_hash == expected_hash


def check_signature(signing_key, message, signature, chain):
    if signing_key is None or message is None or signature is None:
        return False
    message = BitcoinMessage(message)
    try:
        lock.acquire()
        # obtain lock while modifying global state
        bitcoin.SelectParams(chain.name)
        return VerifyMessage(signing_key, message, signature)
    finally:
        lock.release()


def check_not_expired(expiration_date):
    if not expiration_date:
        return True
    # compare to current time. If expires_date is timezone naive, we assume UTC
    now_tz = pytz.UTC.localize(datetime.utcnow())
    return now_tz < expiration_date
