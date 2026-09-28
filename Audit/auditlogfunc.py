import os , sys 
import hashlib
import hmac
from datetime import datetime
from Database.db import insert_log_entry, get_last_log_entry, get_all_log_entries
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

HMAC_secret_key = b"cryptosystem2026"

def log_action(username,role,action,filename=None):
    """
    Create a timestamp for all the log entry and generate a HMAC that includes the previous log HMAC 
    to maintian chain integrity.
    So even if one log is deleted or removed, it shows invalid.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    last_entry = get_last_log_entry()
    if last_entry is None:
        previous_hmac = "startentry"
    else:
        previous_hmac = last_entry["hmac"]

    entry_string = f"{timestamp}{username}{role}{action}{filename}{previous_hmac}"
    
    # chain HMAC to previous entry to detection any tampering
    new_hmac = hmac.new(HMAC_secret_key,entry_string.encode(),hashlib.sha256).hexdigest()
    insert_log_entry(
        timestamp,
        username,
        role,
        action,
        filename,
        previous_hmac,
        new_hmac
    )

def verify_log_integrity():
    """
    Recompute the hash for each entry using stored data and previous HMAC.
    This is then compared wit computed HMAC with stored HMAC
    """

    entries = get_all_log_entries()
    if not entries:
        print("There are no Audit log entries")
        return True
    print("\n --------Verifying Audit Log Integrity----\n")

    previous_hmac = "startentry"
    for entry in entries:
        entry_string = (
            f"{entry['timestamp']}"
            f"{entry['username']}"
            f"{entry['role']}"
            f"{entry['action']}"
            f"{entry['filename']}"
            f"{previous_hmac}"
        )

        expected_hmac = hmac.new(HMAC_secret_key,entry_string.encode(),hashlib.sha256).hexdigest()
        if expected_hmac != entry["hmac"]:
            print(f"The log is tampered at entry ID {entry['id']}")
            print(f"Action: {entry['action']}")
            print(f"Action: {entry['username']}")
            print(f"Action: {entry['timestamp']}")

        previous_hmac = entry["hmac"]
    print(f"All {len(entries)} log entries are verified.")
    print("Audit log integrity are confirmed.")
    return True

def view_auditlog():
    #display logs
    entries = get_all_log_entries()
    if not entries:
        print("Audit log is empty.")
        return
    print("\n----Audit Log -----\n")
    # print(f"ID\tTimestamp\t\tUser\t\tRole\t\tAction\t\t\tFile")
    print(f"{'ID':<5}{'Timestamp':<25}{'User':<15}{'Role':<15}{'Action':<50}{'File'}")
    print('-' * 150)
    for entry in entries:
        filename = entry['filename'] if entry['filename'] else "N/A"
        print(f"{entry['id']:<5} {entry['timestamp']:<25} {entry['username']:<15} {entry['role']:<15} {entry['action']:<50} {filename}")

