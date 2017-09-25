"""
Verify blockchain certificates (http://www.blockcerts.org/)

Overview of verification steps
- Check integrity: TODO: json-ld normalizatio
- Check signature (pre-v2)
- Check whether revoked
- Check whether expired
- Check authenticity

"""
import json

from cert_schema import Chain, UnknownChainError
from cert_schema import model
from cert_schema import is_mainnet_address
from cert_schema.model import TransactionSignature

from cert_verifier import connectors
from cert_verifier.checks import create_verification_steps


def to_chain(anchor_type, address):
    """
    Converts the anchor type in the Blockcert signature to a Chain. In next version of Blockcerts schema we will be able
    to write XTNOpReturn for testnet
    :param chain:
    :return:
    """

    if anchor_type == 'REGOpReturn':
        return Chain.regtest
    elif anchor_type == 'MockOpReturn':
        return Chain.mocknet
    elif anchor_type == "BTCOpReturn":
        is_mainnet = is_mainnet_address(address)
        if is_mainnet:
            return Chain.mainnet
        else:
            return Chain.testnet
    else:
        raise UnknownChainError('Chain not recognized from anchor type: ' + anchor_type)


def verify_certificate(certificate_model):
    # lookup issuer-hosted information
    issuer_info = connectors.get_issuer_info(certificate_model)

    anchor = next(sig for sig in certificate_model.signatures if isinstance(sig, TransactionSignature))
    if anchor and anchor.merkle_proof:
        # choose first anchor type because there is only 1
        anchor_type = anchor.merkle_proof.proof_json['anchors'][0]['type']
    else:
        # pre-v1.2 backcompat
        anchor_type = "BTCOpReturn"
    chain = to_chain(anchor_type, issuer_info.issuer_keys[0].public_key)
    # lookup transaction information

    connector = connectors.createTransactionLookupConnector(chain)
    transaction_info = connector.lookup_tx(certificate_model.txid)

    # create verification plan
    verification_steps = create_verification_steps(certificate_model, transaction_info, issuer_info, chain)

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

    # This one should pass
    result = verify_certificate_file('../tests/data/2.0/valid.json')
    print(result)
