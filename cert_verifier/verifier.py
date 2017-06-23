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

from cert_schema import model
from cert_schema import parse_chain_from_address

from cert_verifier import connectors
from cert_verifier.checks import create_verification_steps


def verify_certificate(certificate_model):
    # lookup issuer-hosted information
    issuer_info = connectors.get_issuer_info(certificate_model)

    # lookup transaction information
    chain = parse_chain_from_address(issuer_info.issuer_keys[0].public_key)
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
    result = verify_certificate_file('../tests/data/2.0/valid-2.0.json')
    print(result)
