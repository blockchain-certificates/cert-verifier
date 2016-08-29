import binascii
import json
import logging
import sys

import hashlib
import requests
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
from cert_schema.schema_tools import schema_validator
from merkleproof import utils
from merkleproof.MerkleTree import sha256
from pyld import jsonld
from connectors import BlockcypherConnector

unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    unhexlify = lambda h: binascii.unhexlify(h.encode('utf8'))
    hexlify = lambda b: binascii.hexlify(b).decode('utf8')


class Error(Exception):
    """Base class for exceptions in this module"""
    pass


class InvalidTransactionError(Error):
    pass


def check_issuer_signature(signing_key, uid, signature):
    if signing_key is None or uid is None or signature is None:
        return False

    message = BitcoinMessage(uid)
    return VerifyMessage(signing_key, message, signature)


def compute_v1_hash(doc):
    doc_bytes = doc
    if not isinstance(doc, (bytes, bytearray)):
        doc_bytes = doc.encode('utf-8')
    return hashlib.sha256(doc_bytes).hexdigest()


def compute_v2_hash(cert_json):
    normalized = jsonld.normalize(cert_json, {'algorithm': 'URDNA2015', 'format': 'application/nquads'})
    hashed = sha256(normalized)
    return hashed


def compare_hashes(hash1, hash2):
    if hash1 in hash2 or hash1 == hash2:
        return True
    return False


def get_issuer_keys(signer_url):
    r = requests.get(signer_url)
    remote_json = None
    if r.status_code != 200:
        logging.error('Error looking up issuer keys at url=%s, status_code=%d', signer_url, r.status_code)
    else:
        remote_json = r.json()
        logging.info('Found issuer keys at url=%s', signer_url)
    return remote_json


def verify_v2(signed_local_json):
    connector = BlockcypherConnector('testnet')
    verify_response = []

    # check the proof before doing anything else
    validate_receipt = utils.validate_proof(signed_local_json['receipt']['proof'],
                        signed_local_json['receipt']['targetHash'],
                        signed_local_json['receipt']['merkleRoot'], sha256)

    if not validate_receipt:
        verify_response.append(('Verifying receipt', False))
        verify_response.append(("Verified", False))
        return verify_response

    transaction_id = signed_local_json['receipt']['anchors'][0]['sourceId']
    transaction_data = connector.lookup_tx(transaction_id)

    if not transaction_data:
        verify_response.append(('Looking up by transaction_id', False))
        verify_response.append(("Verified", False))
        return verify_response

    verify_response.append(("Fetching hash in OP_RETURN field", "DONE"))

    # compute local hash
    local_hash = compute_v2_hash(signed_local_json['document'])
    verify_response.append(("Computing SHA256 digest of local certificate", "DONE"))

    # compare local and remote hashes
    target_hash = signed_local_json['receipt']['targetHash']
    compare_target_hash_result = compare_hashes(local_hash, target_hash)
    verify_response.append(("Comparing local and blockchain hashes", compare_target_hash_result))

    # check merkle root
    merkle_root = signed_local_json['receipt']['merkleRoot']
    remote_hash = transaction_data.script
    compare_merkle_root_result = compare_hashes(merkle_root, remote_hash)
    verify_response.append(("Comparing receipt merkle root with blockchain", compare_target_hash_result))

    # check author
    signer_url = signed_local_json['document']['certificate']['issuer']['id']
    uid = signed_local_json['document']['assertion']['uid']
    signature = signed_local_json['document']['signature']
    keys = get_issuer_keys(signer_url)
    signing_key = keys['issuer_key'][0]['key']
    revocation_address = keys['revocation_key'][0]['key']
    author_verified = check_issuer_signature(signing_key, uid, signature)
    verify_response.append(("Checking signature", author_verified))

    # check if it's been revoked by the issuer
    revoked = revocation_address in transaction_data.revoked_addresses
    verify_response.append(("Checking not revoked by issuer", not revoked))

    verified = compare_target_hash_result and compare_merkle_root_result and author_verified and not revoked
    verify_response.append(("Verified", verified))
    return verify_response


def verify_v1(transaction_id, signed_local_json, signed_local_file):
    connector = BlockcypherConnector('testnet')
    verify_response = []

    transaction_info = connector.lookup_tx(transaction_id)

    if not transaction_info:
        verify_response.append(('Looking up by transaction_id', False))
        verify_response.append(("Verified", False))
        return verify_response

    verify_response.append(("Fetching hash in OP_RETURN field", "DONE"))

    # compute local hash
    local_hash = compute_v1_hash(signed_local_file)
    verify_response.append(("Computing SHA256 digest of local certificate", "DONE"))

    # compare hashes
    compare_hash_result = compare_hashes(local_hash, transaction_info.script)
    verify_response.append(("Comparing local and blockchain hashes", compare_hash_result))

    # check author
    signer_url = signed_local_json['document']['certificate']['issuer']['id']
    uid = signed_local_json['document']['assertion']['uid']
    signature = signed_local_json['document']['signature']

    keys = get_issuer_keys(signer_url)
    signing_key = keys['issuer_key'][0]['key']
    revocation_address = keys['revocation_key'][0]['key']
    author_verified = check_issuer_signature(signing_key, uid, signature)
    verify_response.append(("Checking signature", author_verified))

    # check if it's been revoked by the issuer
    revoked = revocation_address in transaction_info.revoked_addresses
    verify_response.append(("Checking not revoked by issuer", not revoked))

    verified = compare_hash_result and author_verified and not revoked
    verify_response.append(("Verified", verified))
    return verify_response


if __name__ == "__main__":

    # TODO: validate before running

    #schema_updater.update('sample_data/1.1.0/sample_signed_cert-1.1.0.json',
    #                      'sample_data/1.2.0/sample_signed_cert-1.2.0.json-new')

    with open('sample_data/1.2.0/sample_signed_cert-1.2.0.json') as cert_file:
        cert_json = json.load(cert_file)
        schema_validator.validate_v1_2_0(cert_json)
        result = verify_v2(cert_json)
        print(result)


    with open('sample_data/1.1.0/sample_signed_cert-1.1.0.json', 'rb') as cert_file:
        result = verify_v1('c5e240974c3ab4dc0d85bb28cb8a7c87a1a250532b8f985e3960ef4a23244a6a', cert_json, cert_file.read())
        print(result)