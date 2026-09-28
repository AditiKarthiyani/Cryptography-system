import os
import sys
from CryptoFunctions.encryption import encrypt_data,decrypt_data, show_available_files
from Audit.auditlogfunc import log_action

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
encrypted_directory = os.path.join(base_directory, 'Data', 'encrypted')

def clinician_menu(session):
    #clinician menu options
    username = session["username"]
    role = session["role"]
    while True:
        print("\n" + "-" * 50)
        print("        Clinician Menu   ")
        print("-" * 50)
        print("1. Upload patient dataset")
        print("2. Retrieve patient dataset")
        print("3. Logout")
        print("=" * 50)

        choice = input("Enter your choice (1-3):").strip()

        if choice == "1":
            upload_dataset(session) 
        elif choice == "2":
            retrieve_dataset(session)
        elif choice == "3":
            print(f"\n Logging out {username}.")
            log_action(username,role,"logged out")
            break 
        else:
            print("Invalid choice. Please enter from 1-4.")

def upload_dataset(session):
    """
    Upload the data by typing in the terminal, once completed you close it by typing
    "END". 
    """
    username = session["username"]
    role = session["role"]

    print("\n--Upload patient data in here --")
    print("NOTE - This is in compliance with GDPR and will be encrypted and stored securely.")
    
    record_name = input("Enter a name for this record (e.g patient_02x):").strip()
    if not record_name:
        print("No record name entered.")
        return
    
    print("Enter data and type END on a new line when finished.")
    
    lines =[]
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)

    patient_data = "\n".join(lines)

    if not patient_data:
        print("No data has been entered.")
        return
    # string into bytes for encryption
    plaintextdata = patient_data.encode()
    #encypt the data
    filename = encrypt_data(plaintextdata,username,username,record_name)

    if filename:
        log_action(username,role,"uploaded encrypted dataset",filename)
        print(f"Dataset is encrypted and saved.")
        print(f"Action is recorded in audit log")

def retrieve_dataset(session):
    """
    The data inputted is also retrieved and shown to the clinician.
    Presented a list of files which is selected by inputting the number.
    """
    username = session["username"]
    role = session["role"]
    print("\n -- Retreieve dataset.--")

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
        print("\n -- Decrypted data ---")
        print(plaintextdata.decode())
        print("------------------------")

        log_action(username,role,"retrieved and decrypted patient dataset",filename)
        print("Action is recorded in audit log.")


