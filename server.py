import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# 1. Agree on public parameters (p and g) - Use a safe, pre-defined group
# For a production-grade application, use large, standardized parameters (e.g., RFC 3526 group 14)
# We'll use a small, simple one for demonstration purposes.
# In a real-world scenario, you might generate these once and hardcode them or use a library function
parameters = dh.generate_parameters(generator=2, key_size=1024)

def run_server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # 2. Server generates its own DH private/public key pair
            server_private_key = parameters.generate_private_key()
            server_public_key = server_private_key.public_key()
            
            # Serialize the server's public key to send to the client
            server_public_bytes = server_public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            
            # 3. Send server's public key and receive client's public key
            conn.sendall(server_public_bytes)
            
            client_public_bytes = conn.recv(1024)
            client_public_key = load_pem_public_key(client_public_bytes)

            # 4. Compute the shared secret key
            shared_key = server_private_key.exchange(client_public_key)
            
            # Derive a symmetric encryption key from the shared secret
            # HKDF is used to ensure the key is the correct size for AES
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32, # AES-256 key length
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            
            print(f"Shared secret established. Key: {derived_key.hex()}")

            # 5. Receive and decrypt a message
            iv = conn.recv(16) # Receive the Initialization Vector
            encrypted_message = conn.recv(1024)

            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
            
            print(f"Decrypted Message: {decrypted_message.decode()}")

if __name__ == "__main__":
    run_server()
