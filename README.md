# Secure PDF Encryption Project  
**AES-256-GCM • SHA-256 • ECDSA (P-256)**  

---

## Overview

A Python-based application to secure PDF documents through encryption and digital signatures.  

The system ensures:  

- **Confidentiality** – AES-256-GCM encryption  
- **Integrity** – SHA-256 hashing  
- **Authenticity & Non-Repudiation** – ECDSA digital signatures  

Designed with a simple Tkinter GUI, the project demonstrates practical cryptographic integration in a desktop environment.  

---

## Features

- Encrypt PDF files securely using AES-256-GCM  
- Generate SHA-256 hashes of encrypted files  
- Sign files digitally with ECDSA (P-256)  
- Verify signatures and decrypt only if validation succeeds  
- Intuitive graphical interface for ease of use  

---

## How It Works

1. The PDF is encrypted with AES-256-GCM.  
2. A SHA-256 hash of the encrypted file is generated.  
3. The hash is signed using an ECDSA private key.  
4. During verification, the signature is checked using the public key.  
5. Only valid signatures allow decryption, ensuring authenticity and integrity.  

---

## Usage

Run the application:


python main.py
Then select a PDF file and choose:  

- **Encrypt & Sign**  
- **Verify & Decrypt**  

---

## Development Environment

**Language:** Python 3  

**Libraries:**  
- pycryptodome  
- hashlib  
- ecdsa  
- tkinter  
- Pillow  
- base64  
- os  

---

## Security Model

| Property       | Mechanism                  |
|----------------|---------------------------|
| Confidentiality| AES-256-GCM               |
| Integrity      | SHA-256 + GCM authentication |
| Authenticity   | ECDSA Signature           |
| Non-repudiation| ECDSA Signature           |

---

## Conclusion

A practical and secure system demonstrating the integration of symmetric encryption, cryptographic hashing, and asymmetric signatures to protect PDF documents.

