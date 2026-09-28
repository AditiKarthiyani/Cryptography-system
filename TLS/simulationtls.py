import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

"""
The function simulates a TLS handshake and certifcate verification
In a real-life system, TLS 1.3 will establish a secure channel
"""

def simulate_TLS():
    print("\n" +"="*40)
    print("   TLS Handshake simulation.")
    print("="*50)

    print("\n [STEP 1] The certifcate is being displayed..")
    print("Subject : Clinicial Research Platform System")
    print("Issued By : ClinicalResearch-xx")
    print("Issued To: Localxxx")
    print("Valid From: 2026-04-23")
    print("Valid To: 2027-04-23")
    print("Serial no : 1adk:4fnf7:49fhd")
    
    print("\n [STEP 2] Verifying certificate....")
    print("...... Certificate signature is verified..")
    print("...... Certificate is within the validity period.")

    print("\n [STEP 3] Key exchange..")
    print(" Secure session key is established.")

    print("\n [STEP 4] Secure channel is now established..")
    print("\n Protocol - TLS 1.3")
    print("Data is transmistted over encrypted channel.")
    
    print("\n" +"="*40)
    print("  TLS Handshake Complete.")
    

