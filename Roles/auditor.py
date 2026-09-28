import os, sys, json, base64
from CryptoFunctions.keys import verify_certificate, load_certificate
from CryptoFunctions.signatures import verifying_signature
from Audit.auditlogfunc import log_action,view_auditlog,verify_log_integrity

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
encrypted_directory = os.path.join(base_directory, 'Data', 'encrypted')

def auditor_menu(session):
    #auditor menu
    username = session["username"]
    role = session["role"]
    while True:
        print("\n" + "-" * 50)
        print("        Auditor Menu   ")
        print("-" * 50)
        print("1. Verify a digital signature")
        print("2. Verify audit log integrity")
        print("3. View audit log entries")
        print("4. Logout")
        print("=" * 50)

        choice = input("Enter your choice (1-4):").strip()

        if choice == "1":
            verify_signature(session) 
        elif choice == "2":
            verify_log_integrity()
        elif choice == "3":
            view_auditlog()
        elif choice == "4":
            print(f"\n Logging out {username}.")
            log_action(username,role,"logged out")
            break 
        else:
            print("Invalid choice. Please enter from 1-4.")

def verify_signature(session):
    """
    The auditor can verify signatures from a list of files.
    When a file is selected, from inputting the option, shows the validity.
    """
    username = session["username"]
    role = session["role"]

    print("\n-- Verify digital signature --")
    print(" The verification is only using public keys. ")
    print(" The auditor does not get to access plaintext data. ")
    
    sig_files = show_signature_files()
    if not sig_files:
        return
    choice = input("Select file number:").strip()

    try:
        index = int(choice) - 1 
        if index < 0 or index >= len(sig_files):
            print("Invalid Selection.")
            return
        sig_filename=sig_files[index]
    except ValueError:
        print("Please enter a number.")

    sig_path = os.path.join(encrypted_directory, sig_filename)
    with open(sig_path, 'r') as f:
        sig_bundle = json.load(f)
    
    signer = sig_bundle["signer"]
    signature = base64.b64decode(sig_bundle["signature"])
    data_hash = sig_bundle["data_hash"]

    #verify the certificate

    print(f"\n----Verifying {signer} Digital Certificate----")
    is_valid_cert = verify_certificate(signer)
    
    if not is_valid_cert:
        print("Error - the certifiate in invalid.")
        log_action(username,role,f"certificate invalid for{signer}",sig_filename)
        return
    
    cert = load_certificate(signer)
    print(f"Subject: {cert['subject']}")
    print(f"Issued By: {cert['issued_by']}")
    print(f"Valid Until: {cert['valid_until']}")
    print(f"Algorithm: {cert['algorithm']}")
    print(f"The Certificate is verified. Procced to sign.")
    print('-' * 50)
    
    #verify the signature
    print(f"\nVerifying signature ..")
    print(f"Signer: {signer}")
    print(f"File:{sig_bundle['filename']}")

    result= verifying_signature(data_hash,signature,signer)
    if result:
        print(f"Signature is valid")
        print(f"Data is authentic and was signed by {signer}.")
        log_action(username,role,f"Verified signature - signer:{signer}",sig_filename)
    else:
        print(f"Signature is invalid")
        print(f"Data is either tamperd with or not signed.")
        log_action(username,role,f"verified signature is not valid - signer: {signer}",sig_filename)

    
def show_signature_files():
    #display the files 
    if not os.path.exists(encrypted_directory):
        print("There are no signature files found.")
        return []
    sig_files =[
        files for files in os.listdir(encrypted_directory)
        if files.endswith('.sig')
    ]

    print("Available signature file(s):")
    for i,f in enumerate(sig_files,1):
        print(f"{i}.{f}")
    print()
    return sig_files
