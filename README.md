# Quest 2: Encrypting and Decrypting using RSA-OAEP with Authenticity
*A Cybersecurity Quest for the Intellectuals and the Bold*

**Welcome, fellow crypto adventurer!**

You have stumbled upon a secure spellbook that lets you *encrypt messages and sign them for authenticity* using the mighty powers of **RSA-OAEP** for encryption and **RSA-PSS** for digital signatures that enables you to transmit messages that guarantees both **confidentiality** and **authenticity**.

## Quest Description: RSA Encrypt-then-Sign with Authenticity

This quest aims to create a spellbook that implements an encrypt-then-sign scheme for a secure message transmission using **RSA-OAEP** for encryption and **RSA-PSS** for digital signatures. The **spellbook reads a short ASCII message (up to 140 characters)** from a file, *encrypts it*, *signs the ciphertext*, then *verifies and decrypts the message*.

## Quest Spellbook Features

**Separate Key Pairs** (Generates two RSA key pairs)
- One key pair for encryption/decryption (RSA-OAEP).
- Another for signing/verification (RSA-PSS).

**Encrypt-then-Sign/Verify-then-Decrypt Scheme:**
- Encrypts the message using RSA-OAEP.
- Signs the ciphertext with RSA-PSS.
- The process is reversed during decryption after verifying the signature.

**File-Based I/O:**
  - Reads the input message from `message.txt`
  - Saves generated keys in PEM format: `enc_private_key.pem`, `enc_public_key.pem`, `sign_private_key.pem`, `sign_public_key.pem`
  - Outputs Base64-encoded ciphertext and signature to `ciphertext_and_signature.txt`
  - Saves the decrypted message to `decrypted.txt`

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

## Quest Notes

- **Key Overwrite:**

   Each run generates new key pairs, so existing key files will be overwritten. Modify the code if persistent keys are required.

- **Output Files:**

   All output files will be created in the project directory.

## License

This project is licensed under the MIT License.
