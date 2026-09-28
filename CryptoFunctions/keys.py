import os, json
import sys, datetime, base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
keys_directory = os.path.join(base_directory, 'Data', 'Keys')

def generate_keypairs(username,password):
    #Generate RSA key pairs for encryption and signature

    for key_type in ["enc", "sign"]:
        key = RSA.generate(2048)

        # To encrypt the .pem file, the private key
        private_path = os.path.join(keys_directory, f"{username}_{key_type}_private.pem")
        with open(private_path, 'wb') as f:
            f.write(key.export_key(
                passphrase=password.encode(),
                pkcs=8,
                protection="scryptAndAES256-CBC"
            ))

        public_path = os.path.join(keys_directory, f"{username}_{key_type}_public.pem")
        with open(public_path, 'wb') as f:
            f.write(key.publickey().export_key())

    print(f"RSA keypairs generated for {username}")

def load_private_key(username, key_type,password):
    #Load a private key

    path = os.path.join(keys_directory, f"{username}_{key_type}_private.pem")
    with open(path, 'rb') as f:
        return RSA.import_key(f.read(), passphrase=password.encode())


def load_public_key(username, key_type):
    #Load a public key

    path = os.path.join(keys_directory, f"{username}_{key_type}_public.pem")
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())    

def generate_self_signed_certificate(username,password):
    
    """
    This is a self-signed certificate created using x509. 
    In a real-life system, a CA will be issuing this.
    Since this is a self-signed certificate, the subject and issuer are the same.
    """
    
    public_key = load_public_key(username, "sign")
    private_key = load_private_key(username, "sign",password)

    now= datetime.datetime.now()
    #validity for a year
    valid_until = now + datetime.timedelta(days=365)

    certificate={
        "version": "X.509 vs (simulated certificate)",
        "subject": username,
        "issued_by": username,
        "valid_from": now.strftime("%Y-%m-%d"),
        "valid_until": valid_until.strftime("%Y-%m-%d"),
        "public_key" : public_key.export_key().decode(),
        "algorithm": "SHA256-with-RSA",
        "serial_no":  f"01:aaa:{username[:2].upper()}:DF:33:3T"
                               
    }

    cert_data = json.dumps({a:b for a, b in certificate.items()}, sort_keys = True).encode()
    hash_obj = SHA256.new(cert_data)

    #signed using the private key
    signature = pss.new(private_key).sign(hash_obj)
    certificate["signature"] = base64.b64encode(signature).decode()

    cert_path = os.path.join(keys_directory, f"{username}_certificate.json")
    with open(cert_path,'w') as f:
        json.dump(certificate,f,indent =4)
    
    print(f" Self-signed certificate for {username}")
    return certificate

def load_certificate(username):
    cert_path = os.path.join(keys_directory, f"{username}_certificate.json")
    with open(cert_path,'r') as f:
        return json.load(f)
    
def verify_certificate(username):
    certificate = load_certificate(username)

    now = datetime.datetime.now()
    valid_until = datetime.datetime.strptime(certificate["valid_until"],"%Y-%m-%d")
    #verify the validity of date
    if now > valid_until:
        print(f" Error - Certificate for {username} has expired.")
        return False
    public_key = load_public_key(username,"sign")
    signature = base64.b64decode(certificate["signature"])

    cert_data = json.dumps({a:b for a,b in certificate.items() if a != "signature"},sort_keys=True).encode()

    hash_obj = SHA256.new(cert_data)

    try:
        pss.new(public_key).verify(hash_obj,signature)
        return True
    except (ValueError,TypeError):
        print(f"Certificate signature is invalid for{username}.")
        return False
