import os 
import sys
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from CryptoFunctions.keys import load_public_key
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
encrypted_directory = os.path.join(base_directory, 'Data', 'encrypted')

def encrypt_data(plaintext, recipient_username, sender_username,record_name=None):
    os.makedirs(encrypted_directory,exist_ok=True)

    # encrypt the data with AES-256-GCM 
    session_key = get_random_bytes(32)
    nonce = get_random_bytes(16)

    aes_cipher = AES.new(session_key,AES.MODE_GCM,nonce=nonce)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    recipient_public_key = load_public_key(recipient_username, "enc")
    
    #encrypt the session key with RSA - OAEP padding
    rsa_cipher = PKCS1_OAEP.new(recipient_public_key)
    encrypted_session_key = rsa_cipher.encrypt(session_key)

    bundle={
        "encrypted_session_key" : base64.b64encode(encrypted_session_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "encrypted_by":sender_username,
        "encrypted_for":recipient_username
    }

    if record_name:
        filename = f"{record_name}.json"
    else:
        filename = f"{sender_username}_for_{recipient_username}.json"

    bundle_path = os.path.join(encrypted_directory,filename)
    with open(bundle_path,'w') as f:
        json.dump(bundle,f,indent=4)
    
    print(f"Data encrypted and saved as {filename}")
    return filename

def decrypt_data(filename,privatekey):
    bundle_path= os.path.join(encrypted_directory,filename)
    with open(bundle_path,'r') as f:
        bundle =json.load(f)

    encrypted_session_key = base64.b64decode(bundle["encrypted_session_key"])
    nonce = base64.b64decode(bundle["nonce"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
    tag= base64.b64decode(bundle["tag"])

    rsa_cipher = PKCS1_OAEP.new(privatekey)
    
    #decrypt the key using RSA - private key
    session_key = rsa_cipher.decrypt(encrypted_session_key)

    aes_cipher = AES.new(session_key,AES.MODE_GCM,nonce=nonce)

    try:
        #decrypt the data using AES
        plaintext = aes_cipher.decrypt_and_verify(ciphertext,tag)
    except ValueError:
        print("ERROR Decryption has failed - data may have been tampered with.")
        return None
    print("Data decrypted and data integrity verified.")
    return plaintext

def show_available_files(username):
   
    """shows all the available files to the users in a form of a list"""
    os.makedirs(encrypted_directory, exist_ok=True)
    files = []
    for f in os.listdir(encrypted_directory):
        if not f.endswith('.json'):
            continue

        filepath = os.path.join(encrypted_directory, f)
        try:
            with open(filepath, 'r') as file:
                bundle = json.load(file)
            if bundle.get("encrypted_by") == username:
                files.append(f)
        except:
            continue
    
    if not files:
        print("No encrypted files found for your account.")
        return
    
    print("\n The encrypted files.")
    for i,f in enumerate(files,1):
        print(f"{i}.{f}")
    print()
    return files
