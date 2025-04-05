# Quest 2: Encrypting and Decrypting using RSA-OAEP with Authenticity
*A Cybersecurity Quest for the Intellectuals and the Bold*

**Welcome, fellow crypto adventurer!**

You have stumbled upon a secure spellbook that lets you *encrypt messages and sign them for authenticity* using the mighty powers of **RSA-OAEP** for encryption and **RSA-PSS** for digital signatures that enables you to transmit messages that guarantees both **confidentiality** and **authenticity**.

## Quest Introduction

This quest aims to create a spellbook that implements an encrypt-then-sign scheme for a secure message transmission using **RSA-OAEP** for encryption combined with **RSA-PSS** for digital signatures. The **spellbook reads a short ASCII message (up to 140 characters)** from a file, *encrypts it*, *signs the ciphertext*, then *verifies and decrypts the message* to ensure message **authenticity**. Python's `cryptography` package is utilized instead of hand-coding cryptographic algorithms.

## Quest Spellbook Features
### **Design Overview**
**Encryption**
- The **RSA-OAEP** is the algorithm used.
- The purpose is to securely encrypt the message.

**Signing**
- The **RSA-PSS** is the algorithm used.
- The purpose is to provide authenticity to the encrypted message by signing the ciphertext.

**Schemes**

1. **Encrypt-then-Sign**
   - Encrypt the plaintext message using the encryption key (RSA-OAEP).
   - Then, sign the resulting ciphertext with a separate signing key (RSA-PSS).

2. **Verify-then-Decrypt**
   - Verify the signature with the signing public key.
   - Upon successful verification, decrypt the ciphertext using the encryption private key.

### **Key Generation and Management**

**Separate Key Pairs** (Generates two RSA key pair)
- Encryption/Decryption Keys: Generated using RSA with OAEP padding.
- Signing/Verification Keys: Generated using RSA with PSS padding.

**Key Storage**
- Generated keys are saved in PEM format: `enc_private_key.pem`, `enc_public_key.pem`, `sign_private_key.pem`, `sign_public_key.pem`

### **Input/Output Handling**

**Input Message**
- Instead of prompting the crypto adventurer, the program reads the input message from `message.txt`

**Output Files**
- Outputs base64-encoded ciphertext and signature to `ciphertext_and_signature.txt` file.
- Saves the decrypted message to `decrypted.txt` file.

## Quest Requirements

You are required to meet these requirements to proceed with the quest.
- Python 3.x
- [cryptography](https://cryptography.io/en/latest/) library

If *cryptography library* does not exist in your machine yet, install using pip:

`pip install cryptography`

## How to Utilize the Quest Spellbook

1. **Clone the Repository:**

   `git clone https://github.com/Exalt24/cmsc-134-mp2.git`

   `cd cmsc-134-mp2`

2. **(Optional) Create and Activate a Virtual Environment:**

   `python -m venv .venv`
   - On Windows:

     `.venv\Scripts\activate`
   - On macOS/Linux:

     `source .venv/bin/activate`

3. **Write Your Secret Message:**

   Created a file named `message.txt` in the project directory. Put the 140-character (or shorter) ASCII message inside.

4. **Run the Spell:**

   `python rsa_encrypt_decrypt.py`

   The script will:
   - Generate new RSA key pairs (overwriting any existing key files).
   - Encrypt the message from `message.txt` and sign the ciphertext.
   - Save the keys, ciphertext with signature, and decrypted message to their respective files.
   - The spell prints confirmation messages about saved keys and files in the terminal.
   - The console output displays the decrypted message which is also stored in `decrypted.txt` file.

## Files Provided
**Keys**
- `enc_private_key.pem` and `enc_public_key.pem` for encryption.
- `sign_private_key.pem` and `sign_public_key.pem` for signing.

**Message Files**
- `message.txt` for the input message.

**Encrypted Data**
- `ciphertext_and_signature.txt` for the base64-encoded ciphertext and signature.

**Decrypted Output**
- `decrypted.txt` for the decrypted message. The content inside this file should match with the content of `message.txt` indicating that everything is working correctly.


## Quest Notes

- **Key Overwrite:**

   Each run generates new key pairs, so existing key files will be overwritten.

- **Output Files:**

   All output files are provided in the project directory.

## License

This project is licensed under the MIT License.
