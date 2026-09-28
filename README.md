# Secure Clinical Research Platform

A Python-based secure clinical research platform demonstrating the application
of cryptographic techniques to protect sensitive patient data and research
findings.

## Overview

This project simulates a secure platform for cross-border clinical research
collaboration. It uses role-based access control and multiple cryptographic
mechanisms to provide confidentiality, integrity, authentication and
accountability.

The system has three user roles:

- Clinician – uploads and retrieves encrypted patient datasets.
- Researcher – encrypts, signs and retrieves research findings.
- Auditor – verifies digital signatures, checks audit-log integrity and views
  audit logs without accessing plaintext data.

## Security Features

The project demonstrates:

- AES-256-GCM for data encryption
- RSA-2048 with OAEP for encryption-key protection
- RSA-PSS for digital signatures
- SHA-256 hashing
- Argon2 password hashing
- HMAC-SHA256 for audit-log integrity
- X.509-style simulated certificates
- Role-Based Access Control (RBAC)
- Simulated TLS 1.3 handshake
- Account lockout after failed login attempts
- Simulated multi-factor authentication
- Key revocation simulation

## System Architecture

### Clinician

1. Logs into the system.
2. Enters patient data.
3. Data is encrypted using AES-256-GCM.
4. The AES session key is protected using RSA-OAEP.
5. The encrypted data is stored in the `Data/encrypted` directory.
6. The clinician can later decrypt their own data.

### Researcher

1. Logs into the system.
2. Their digital certificate is verified.
3. Research findings are hashed using SHA-256.
4. The findings are signed using RSA-PSS.
5. The findings are encrypted using AES-256-GCM.
6. The AES session key is protected using RSA-OAEP.
7. The encrypted findings and signature are stored separately.

### Auditor

The auditor cannot decrypt patient or research data.

Instead, the auditor can:

- Verify digital signatures
- Verify certificate validity
- Check audit-log integrity
- View audit-log entries

## Project Structure

```text
.
├── Main.py
├── Adminkeyrevoke.py
│
├── Authorisation/
│   ├── login.py
│   └── setupaccounts.py
│
├── Audit/
│   └── auditlogicfunc.py
│
├── Database/
│   └── db.py
│
├── CryptoFunctions/
│   ├── encryption.py
│   ├── keys.py
│   └── signatures.py
│
├── Roles/
│   ├── clinician.py
│   ├── researcher.py
│   └── auditor.py
│
├── TLS/
│   └── simulationtls.py
│
└── Data/
    ├── encrypted/
    ├── Keys/
    └── database.db
