import os
import sys
from argon2 import PasswordHasher
from Database.db import insert_user, user_exists
from  CryptoFunctions.keys import generate_keypairs, generate_self_signed_certificate
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

#password is hashed using argon2
ph = PasswordHasher()
credentials = [
    {"username": "nobitha",   "password": "nobitha123!",   "role": "researcher"},
    {"username": "bob",     "password": "bob783!",     "role": "clinician"},
    {"username": "kabir", "password": "kabir789!", "role": "auditor"},
]
def setup_accountpassword():
    for account in credentials:
        username = account["username"]
        password = account["password"]
        role     = account["role"]

        # Check if user already exists or not.
        if user_exists(username):
            print(f"Account '{username}' already exists in the system.")
            continue

        argon2_hash = ph.hash(password)

        # Generate keypairs (encryption + signing)
        generate_keypairs(username,password)

        #generate certificate
        generate_self_signed_certificate(username,password)

        insert_user(username, argon2_hash, role)

        print(f" - Created account: {username} | Role: {role}")

    print("\n=== Account Setup is Complete ===\n")

