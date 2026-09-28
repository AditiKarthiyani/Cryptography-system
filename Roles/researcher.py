import os
import sys
import json, base64
from CryptoFunctions.encryption import encrypt_data, decrypt_data, show_available_files
from CryptoFunctions.signatures import signing_data
from Audit.auditlogfunc import log_action
from CryptoFunctions.keys import load_certificate,verify_certificate

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
encrypted_directory = os.path.join(base_directory, 'Data', 'encrypted')


def researcher_menu(session):
    #researcher menu options
    username = session["username"]
    role = session["role"]
    while True:
        print("\n" + "-" * 50)
        print("        Researcher Menu   ")
        print("-" * 50)
        print("1. Encrypt and sign research findings")
        print("2. Decrypt findings")
        print("3. Logout")
        print("=" * 50)

        choice = input("Enter your choice (1-3):").strip()

        if choice == "1":
            encrypt_and_sign(session) 
        elif choice == "2":
            decrypt_findings(session)
        elif choice == "3":
            print(f"\n Logging out {username}.")
            log_action(username,role,"logged out")
            break 
        else:
            print("Invalid choice. Please enter from 1-3.")

def encrypt_and_sign(session):
    """
    The researcher can type the research findings in the terminal and close it 
    by typing "END".
    The file is then encrypted and signed at the same time. 
    """
    username = session["username"]
    role = session["role"]

    print("\n--Encrypt and sign research finsings --")
    print("NOTE - This is in compliance with GDPR and will be encrypted and signed securely.")
    
    print("----Verifying your Digital Certificate----")
    is_valid_cert = verify_certificate(username)

    if not is_valid_cert:
        print("Error - the certifiate in invalid. Cannot rpocced from here.")
        return
    cert = load_certificate(username)
    print(f"Subject: {cert['subject']}")
    print(f"Issued By: {cert['issued_by']}")
    print(f"Valid Until: {cert['valid_until']}")
    print(f"Algorithm: {cert['algorithm']}")
    print(f"The Certificate is verified. Procced to sign.")
    print('-' * 50)
   
   #name the file the researcher can save it as.
    record_name = input("Enter a name for this research finding (e.g finding_02x):").strip()
    if not record_name:
        print("No record name entered.")
        return
    
    #end the researching findings by typing 'END'
    print("Enter research findings and type END on a new line when finished.")
    lines =[]
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)

    findings = "\n".join(lines)

    if not findings:
        print("No data has been entered.")
        return
    

    plaintextdata = findings.encode()
    #sigining before encryption
    signature, data_hash = signing_data(plaintextdata,session["sign_private_key"])
    
    filename = encrypt_data(plaintextdata,username,username,record_name)

    if filename:
        sig_filename = filename.replace('.json','.sig')
        sig_path = os.path.join(encrypted_directory,sig_filename)
        sig_bundle={
            "signer": username,
            "filename": filename,
            "signature": base64.b64encode(signature).decode(),
            "data_hash": data_hash
        }

        with open(sig_path,'w') as f:
            json.dump(sig_bundle,f,indent=4)

        log_action(username,role,"encrypted and signed research findings",filename)
        print(f"Research findings is encrypted and saved as {filename}.")
        print(f"Signature saved as {sig_filename}")
        print(f"Action is recorded in audit log")

def decrypt_findings(session):
    #Show the decrypted research findings to the researcher.

    username = session["username"]
    role = session["role"]
    print("\n-- Decrypt research findings --")

    files = show_available_files(username)

    if not files:
        return
    
    filename_choice = input(" Select a number from the list of files: ").strip()
    try:
        index =int(filename_choice) - 1
        if index < 0 or index >= len(files):
            print("Invalid selection.")
            return
        filename = files[index]
    except ValueError:
        print("Please enter a valid number.")
        return
    
    plaintextdata = decrypt_data(filename,session["enc_private_key"])
    if plaintextdata:
        print("\n -- Decrypted research findings ---")
        print(plaintextdata.decode())
        print("------------------------")

        log_action(username,role,"decrypted research findings.",filename)
        print("Action is recorded in audit log.")



