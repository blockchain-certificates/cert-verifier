"""
Verify blockchain certificates (http://www.blockcerts.org/)
"""
import binascii
import hashlib
import json
import logging
import sys

import bitcoin
import requests
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
from cert_schema.schema_tools import schema_validator
from merkleproof import utils
from merkleproof.MerkleTree import sha256
from pyld import jsonld
from cert_verifier.errors import *

from cert_verifier.connectors import BlockcypherConnector, createTransactionLookupConnector

unhexlify = binascii.unhexlify
hexlify = binascii.hexlify
if sys.version > '3':
    unhexlify = lambda h: binascii.unhexlify(h.encode('utf8'))
    hexlify = lambda b: binascii.hexlify(b).decode('utf8')




def check_issuer_signature(signing_key, uid, signature):
    if signing_key is None or uid is None or signature is None:
        return False

    message = BitcoinMessage(uid)
    return VerifyMessage(signing_key, message, signature)


def compute_v1_hash(doc_bytes):
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


def verify_v1_2(cert_json, chain='mainnet'):
    connector = createTransactionLookupConnector(chain)
    if chain == 'testnet':
        bitcoin.SelectParams(chain)

    # first ensure this is a valid v1.2 cert
    try:
        schema_validator.validate_v1_2_0(cert_json)
        logging.debug('schema validates against v1.2 schema')
    except Exception as e:
        logging.error('Schema validation failed', e)
        raise InvalidCertificateError('Schema validation failed', e)

    # check the proof before doing anything else
    validate_receipt = utils.validate_receipt(cert_json['receipt'])

    if not validate_receipt:
        raise InvalidCertificateError('Certificate receipt is invalid')
    logging.debug('Receipt is valid')

    try:
        transaction_id = cert_json['receipt']['anchors'][0]['sourceId']
        transaction_data = connector.lookup_tx(transaction_id)
        logging.debug('successfully looked up transaction data')
    except Exception as e:
        raise InvalidCertificateError('Failure looking up transaction', e)

    # compute local hash
    try:
        local_hash = compute_v2_hash(cert_json['document'])
        logging.debug('computed local hash')
    except Exception as e:
        raise InvalidCertificateError('Error computing SHA256 digest of local certificate', e)


    # compare local and receipt targetHash
    target_hash = cert_json['receipt']['targetHash']
    compare_target_hash_result = compare_hashes(local_hash, target_hash)
    if not compare_target_hash_result:
        # TODO: exception?
        raise InvalidCertificateError('Local and target hash did not match')
    logging.debug('local hash matched the targetHash in the receipt')

    # check merkle root against the value on the blockchain
    merkle_root = cert_json['receipt']['merkleRoot']
    remote_hash = transaction_data.script
    compare_merkle_root_result = compare_hashes(merkle_root, remote_hash)
    if not compare_merkle_root_result:
        # TODO: exception?
        raise InvalidCertificateError('The merkleRoot in the receipt did not match the value on the blockchain')
    logging.debug('the receipt merkleRoot matched the value on the blockchain')

    # check author
    signer_url = cert_json['document']['certificate']['issuer']['id']
    keys = get_issuer_keys(signer_url)
    uid = cert_json['document']['assertion']['uid']
    signature = cert_json['document']['signature']

    signing_key = keys['issuer_key'][0]['key']
    revocation_address = keys['revocation_key'][0]['key']

    author_verified = check_issuer_signature(signing_key, uid, signature)
    if not author_verified:
        # TODO: exception?
        raise InvalidCertificateError('Author signature check failed')

    # check if it's been revoked by the issuer
    revoked = revocation_address in transaction_data.revoked_addresses
    if revoked:
        raise InvalidCertificateError('Certificate has been revoked by the issuer')

    logging.debug('All checks have passed; certificate is valid')


def verify_v1_1(cert_file_bytes, transaction_id, chain='mainnet'):
    if chain:
        connector = BlockcypherConnector(chain)
        bitcoin.SelectParams(chain)

    cert_utf8 = cert_file_bytes.decode('utf-8')
    cert_json = json.loads(cert_utf8)

    # first ensure this is a valid v1.1 cert
    schema_validator.validate_v1_1_0(cert_json)

    verify_response = []

    transaction_info = connector.lookup_tx(transaction_id)

    if not transaction_info:
        verify_response.append(('Looking up by transaction_id', False))
        verify_response.append(("Verified", False))
        return verify_response

    verify_response.append(("Fetching hash in OP_RETURN field", "DONE"))

    # compute local hash
    local_hash = compute_v1_hash(cert_file_bytes)
    verify_response.append(("Computing SHA256 digest of local certificate", "DONE"))

    # compare hashes
    compare_hash_result = compare_hashes(local_hash, transaction_info.script)
    verify_response.append(("Comparing local and blockchain hashes", compare_hash_result))

    # check author
    signer_url = cert_json['certificate']['issuer']['id']
    uid = cert_json['assertion']['uid']
    signature = cert_json['signature']

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


def verify_cert_file(cert_file, chain=None, transaction_id=None):
    with open(cert_file, 'rb') as cert_fp:
        contents = cert_fp.read()
        cert_utf8 = contents.decode('utf-8')
        result = verify_cert_contents(cert_utf8, chain, transaction_id)
    return result


def verify_cert_contents(cert_utf8, chain, transaction_id):
    cert_json = json.loads(cert_utf8)
    if '@context' in cert_json:
        result = verify_v1_2(cert_json, chain)
    else:
        if transaction_id is None:
            raise Exception('v1 certificate is not accompanied with a transaction id')
        result = verify_v1_1(cert_utf8, chain, transaction_id)
    return result


if __name__ == "__main__":
    with open('../sample_data/1.2.0/sample_signed_cert-1.2.0.json') as cert_file:
        cert_json = json.load(cert_file)
        result = verify_v1_2(cert_json, 'testnet')
        print(result)

    with open('../sample_data/1.1.0/sample_signed_cert-1.1.0.json', 'rb') as cert_file:
        result = verify_v1_1(cert_file.read(), '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa',  'testnet')
        print(result)

    result = verify_cert_file('../sample_data/1.2.0/sample_signed_cert-1.2.0.json', 'testnet')
    print(result)
    result = verify_cert_file('../sample_data/1.1.0/sample_signed_cert-1.1.0.json', '1703d2f5d706d495c1c65b40a086991ab755cc0a02bef51cd4aff9ed7a8586aa', 'testnet')
    print(result)


