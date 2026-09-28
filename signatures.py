import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from CryptoFunctions.keys import load_public_key
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def signing_data(plaintextdata,private_key):
    """
    Hash the plaintext with SHA-256 
    Then sign it with RSA-PSS
    """
    data_hash = SHA256.new(plaintextdata).hexdigest()
    hash_to_sign = SHA256.new(data_hash.encode())
    signature = pss.new(private_key).sign(hash_to_sign)
    return signature, data_hash

def verifying_signature(data_hash,signature, signer_username):
    """
    Verify the RSA-PSS with the stored hash 
    This is for the auditor
    """
    public_key = load_public_key(signer_username,"sign")
    hash_to_verify = SHA256.new(data_hash.encode())
    try:
        pss.new(public_key).verify(hash_to_verify,signature)
        return True
    except (ValueError,TypeError):
        return False
    


