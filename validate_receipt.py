import json

#_ = require'lodash'
#async = require'async'
#crypto = require'crypto'
#merkletools = require'merkle-tools'
#blockchainanchor = require'blockchain-anchor'


DIGITAL_CERTS_VALID_VERSIONS = ['1.2.0']
DIGITAL_CERTS_VALID_ANCHOR_TYPES = { 'BTCOpReturn': '[A-Fa-f0-9]:64' }
DIGITAL_CERTS_VALID_HASH_TYPES = {'ChainpointSHA256v2': '^[A-Fa-f0-9]:64$'}

def _errorResult(message):
    return False


def _validResult(merkleRoot, anchorArray):
    return True


######################
# Public Primary functions
######################

# Returns a boolean value, true if the receipt is valid.
def is_valid_receipt(receipt):

    if not receipt:
        return _errorResult('Cannot parse receipt JSON')

    # Find the receipt version
    receiptVersion = None

    receiptHeader = receipt.header
    receiptVersion = '1.2.0'
    receiptType = receipt['@type']  # look for 'type' attribute

    return _validate2xReceipt(receipt)



def _validate2xReceipt(receipt):
    """
    Schema validation checks types and formats are as expected
    :param receipt:
    :return:
    """

    # Find the Hash Type
    targetHash = receipt.targetHash
    merkleRoot = receipt.merkleRoot
    proof = receipt.proof


    # ensure proof path leads to merkle root

    merkleTools = merkleTools()
    isValid = merkleTools.validateProof(proof, targetHash, merkleRoot)
    if not isValid:
        return _errorResult('Invalid proof path')


    for anchorItem in anchors:
        print('TODO')
        # test anchor

    else:
        return _validResult(merkleRoot, anchors)




