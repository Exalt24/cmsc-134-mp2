# RSA Encrypt-then-Sign with Authenticity

This project implements an encrypt-then-sign scheme for secure message transmission using RSA-OAEP for encryption and RSA-PSS for digital signatures. The program reads a short ASCII message (up to 140 characters) from a file, encrypts it, signs the ciphertext, then verifies and decrypts the message.

## Features

- **Separate Key Pairs:** Generates two RSA key pairs: one for encryption (RSA-OAEP) and one for signing (RSA-PSS).  
- **Encrypt-then-Sign/Verify-then-Decrypt Scheme:** Encrypts the message using RSA-OAEP, then signs the ciphertext with RSA-PSS. The process is reversed during decryption after verifying the signature.  
- **File-Based I/O:**  
  - Reads the input message from `message.txt`  
  - Saves generated keys in PEM format: `enc_private_key.pem`, `enc_public_key.pem`, `sign_private_key.pem`, `sign_public_key.pem`  
  - Outputs Base64-encoded ciphertext and signature to `ciphertext_and_signature.txt`  
  - Saves the decrypted message to `decrypted.txt`  

## Prerequisites

- Python 3.x  
- [cryptography](https://cryptography.io/en/latest/) library  

Install the dependency using pip:  
`pip install cryptography`

## Setup and Running

1. **Clone the Repository:**  
   `git clone <repository_url>`  
   `cd <repository_directory>`

2. **(Optional) Create and Activate a Virtual Environment:**  
   `python -m venv .venv`  
   - On Windows:  
     `.venv\Scripts\activate`  
   - On macOS/Linux:  
     `source .venv/bin/activate`

3. **Prepare the Message File:**  
   Create a file named `message.txt` in the project directory with your message (max 140 ASCII characters).

4. **Run the Script:**  
   `python rsa_encrypt_decrypt.py`  

   The script will:  
   - Generate new RSA key pairs (overwriting any existing key files).  
   - Encrypt the message from `message.txt` and sign the ciphertext.  
   - Save the keys, ciphertext with signature, and decrypted message to their respective files.

## Notes

- **Key Overwrite:** Each run generates new key pairs, so existing key files will be overwritten. Modify the code if persistent keys are required.  
- **Output Files:** All output files will be created in the project directory.

## License

This project is licensed under the MIT License.
