import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# 1. Agree on public parameters (p and g) - Same as the server
parameters = dh.generate_parameters(generator=2, key_size=1024)

def run_client():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # 2. Client generates its own DH private/public key pair
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key()

        # Serialize the client's public key to send to the server
        client_public_bytes = client_public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        # 3. Receive server's public key and send client's public key
        server_public_bytes = s.recv(1024)
        s.sendall(client_public_bytes)

        server_public_key = load_pem_public_key(server_public_bytes)

        # 4. Compute the shared secret key
        shared_key = client_private_key.exchange(server_public_key)

        # Derive a symmetric encryption key (must match server's derivation)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        print(f"Shared secret established. Key: {derived_key.hex()}")

        # 5. Encrypt and send a message
        message = b"This is a super secret message!"
        iv = os.urandom(16) # Generate a random Initialization Vector
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()

        s.sendall(iv)
        s.sendall(encrypted_message)
        print("Message sent securely.")

if __name__ == "__main__":
    run_client()
