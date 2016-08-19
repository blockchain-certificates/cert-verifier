import binascii
import json
import logging
import sys

import hashlib
import requests
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
from cert_schema.schema_tools import schema_validator


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


def verify(transaction_id, signed_local_json, signed_local_file):
    # TODO: refactor
    r = requests.get(
        "https://blockchain.info/rawtx/%s?cors=true" %
        transaction_id)
    verify_response = []
    verified = False
    if r.status_code != 200:
        logging.error(
            'Error looking up by transaction_id=%s, status_code=%d',
            transaction_id,
            r.status_code)
        verify_response.append(('Looking up by transaction_id', False))
        verify_response.append(("Verified", False))
    else:
        verify_response.append(
            ("Computing SHA256 digest of local certificate", "DONE"))
        verify_response.append(("Fetching hash in OP_RETURN field", "DONE"))
        remote_json = r.json()

        # compare hashes
        local_hash = compute_hash(signed_local_file)
        remote_hash = fetch_hash_from_chain(remote_json)
        compare_hash_result = compare_hashes(local_hash, remote_hash)
        verify_response.append(
            ("Comparing local and blockchain hashes", compare_hash_result))

        # check author
        signer_url = signed_local_json['certificate']['issuer']['id']
        keys = get_issuer_keys(signer_url)
        issuing_address = keys['issuer_key'][0]['key']
        verify_authors = check_author(issuing_address, signed_local_json)
        verify_response.append(("Checking signature", verify_authors))

        # check revocation
        revocation_address = keys['revocation_key'][0]['key']
        not_revoked = check_revocation(remote_json, revocation_address)
        verify_response.append(("Checking not revoked by issuer", not_revoked))

        if compare_hash_result and verify_authors and not_revoked:
            verified = True
        verify_response.append(("Verified", verified))
    return verify_response

def get_issuer_keys(signer_url):
    r = requests.get(signer_url)
    remote_json = None
    if r.status_code != 200:
        logging.error(
            'Error looking up issuer keys at url=%s, status_code=%d',
            signer_url, r.status_code)
    else:
        remote_json = r.json()
        logging.info(
            'Found issuer keys at url=%s', signer_url)
    return remote_json


def get_hash_from_bc_op(tx_json):
    tx_outs = tx_json['out']
    op_tx = None
    for o in tx_outs:
        if int(o.get('value', 1)) == 0:
            op_tx = o
    if not op_tx:
        raise InvalidTransactionError('transaction is missing op_return ')
    hashed_json = unhexlify(op_tx['script'])
    return hashed_json


def check_revocation(tx_json, revoke_address):
    tx_outs = tx_json['out']
    for o in tx_outs:
        if o.get('addr') == revoke_address and o.get('spent') is False:
            return True
    return False


def compute_hash(doc):
    doc_bytes = doc
    if not isinstance(doc, (bytes, bytearray)):
        doc_bytes = doc.encode('utf-8')
    return hashlib.sha256(doc_bytes).hexdigest()


def fetch_hash_from_chain(tx_json):
    hash_from_bc = hexlify(get_hash_from_bc_op(tx_json))
    return hash_from_bc


def compare_hashes(hash1, hash2):
    if hash1 in hash2 or hash1 == hash2:
        return True
    return False


def check_author(address, signed_json):
    uid = signed_json['assertion']['uid']
    message = BitcoinMessage(uid)
    if signed_json.get('signature', None):
        signature = signed_json['signature']
        logging.debug('Found signature for uid=%s; verifying message', uid)
        return VerifyMessage(address, message, signature)
    logging.warning('Missing signature for uid=%s', uid)
    return False


if __name__ == "__main__":
    with open('sample_data/1.1.0/sample_signed_cert-1.1.0.json') as cert_file:
        cert_json = json.load(cert_file)
        schema_validator.validate_v1_1_0(cert_json)


    with open('sample_data/1.1.0/sample_signed_cert-1.1.0.json', 'rb') as cert_file:
        result = verify('d5df311055bf0fe656b9d6fa19aad15c915b47303e06677b812773c37050e35d', cert_json, cert_file.read())
        print(result)