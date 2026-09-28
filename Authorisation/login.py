import os
import sys
import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Database.db import get_user
from CryptoFunctions.keys import load_private_key
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

ph = PasswordHasher()
MFA_code = "68795"

def login():
    """
    Handles the user login.
    Verify username + password which is hashed using Argon2.
    A Simulation of MFA is shown.

    """
    #The users are given 3 attempts to login before the systems denies them
    max_attempts= 3
    attempts =0

    while attempts < max_attempts:
        print("\n=== Login ===\n")

        username = input("Enter username: ").strip()
        #This masks the password that is typed
        password = getpass.getpass("Enter password: ").strip()

        user = get_user(username)

        if user is None:
            attempts +=1
            print("ERROR - Invalid username or password entered.")
            continue
        
        if user["revoked"] == 1:
            print("\n This account has been revoked.")
            return None
        try:
            ph.verify(user["argon2_hash"], password)
        
        except VerifyMismatchError:
            attempts +=1
            print("ERROR - Invalid username or password entered.")
            continue
        # 2 attempts for MFA code
        # failed then back to login    
        mfa_attempt = 0
        max_mfa_attempt = 2
        while mfa_attempt < max_mfa_attempt:
            print(f"\n In a real-life system, this code will be sent to your authenticator app")
            print(f"For the testing purpose, the simulated MFA code is: {MFA_code}\n")

            entered_code = input("Enter MFA code: ").strip()
            if entered_code == MFA_code:
                break
            else:
                mfa_attempt +=1
                remaining = max_mfa_attempt - mfa_attempt
                if remaining > 0:
                    print(f"Invalid MFA code.{remaining} attempt remaining.")
                else:
                    print(f"Invalid MFA code.")
            
        if mfa_attempt == max_mfa_attempt:
            attempts +=1
            print(f"MFA Verification has failed.")
            continue

        enc_private_key  = load_private_key(user["username"], "enc",password)
        sign_private_key = load_private_key(user["username"], "sign",password)
        
        session = {
            "username":         username,
            "role":             user["role"],
            "enc_private_key":  enc_private_key,
            "sign_private_key": sign_private_key
        }

        print(f"\n Login successful. Welcome {username}! Role: {user['role']}\n")
        return session
    
    print("\n Incorrect credentials is entered too many attemps. Access denied.")
    return None
