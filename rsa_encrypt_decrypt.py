import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA key pair for encryption (RSA-OAEP)
def generate_encryption_keys():
    encryption_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return encryption_private_key, encryption_private_key.public_key()

# Generate RSA key pair for signing (RSA-PSS)
def generate_signing_keys():
    signing_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return signing_private_key, signing_private_key.public_key()

# Save key (private or public) to a file in PEM format.
def save_key_to_file(key, filename, is_private=False):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, "wb") as f:
        f.write(pem)
    print(f"Saved key to {filename}")

# Encrypt the message and then sign the ciphertext.
def encrypt_then_sign(message, encryption_public_key, signing_private_key):
    ciphertext = encryption_public_key.encrypt(
        message.encode("ascii"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    signature = signing_private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return ciphertext, signature

# Verify the signature and decrypt the ciphertext.
def verify_then_decrypt(ciphertext, signature, encryption_private_key, signing_public_key):
    try:
        signing_public_key.verify(
            signature,
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        decrypted_message = encryption_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode("ascii")
    except Exception as e:
        print("Error during verification or decryption:", e)
        return None

def main():
    message_file = "message.txt"
    if not os.path.exists(message_file):
        print(f"Error: {message_file} not found. Please create a file with your message.")
        return

    with open(message_file, "r") as f:
        message = f.read().strip()

    if len(message) > 140:
        print("Error: Message exceeds 140 ASCII characters!")
        return

    encryption_private_key, encryption_public_key = generate_encryption_keys()
    signing_private_key, signing_public_key = generate_signing_keys()

    save_key_to_file(encryption_private_key, "enc_private_key.pem", is_private=True)
    save_key_to_file(encryption_public_key,  "enc_public_key.pem",  is_private=False)
    save_key_to_file(signing_private_key,    "sign_private_key.pem", is_private=True)
    save_key_to_file(signing_public_key,     "sign_public_key.pem",  is_private=False)

    ciphertext, signature = encrypt_then_sign(message, encryption_public_key, signing_private_key)

    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    signature_b64 = base64.b64encode(signature).decode("ascii")
    with open("ciphertext_and_signature.txt", "w") as f:
        f.write("Ciphertext (Base64):\n")
        f.write(ciphertext_b64 + "\n")
        f.write("Signature (Base64):\n")
        f.write(signature_b64 + "\n")
    print("Saved ciphertext and signature to ciphertext_and_signature.txt")

    decrypted_message = verify_then_decrypt(ciphertext, signature, encryption_private_key, signing_public_key)
    if decrypted_message is not None:
        with open("decrypted.txt", "w") as f:
            f.write(decrypted_message)
        print("Saved decrypted message to decrypted.txt")
        print("Decrypted message:", decrypted_message)
    else:
        print("Failed to verify or decrypt the message.")

if __name__ == "__main__":
    main()
