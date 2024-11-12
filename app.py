
from flask import Flask, render_template, request, jsonify, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

# Store generated keys in memory
key_storage = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys():
    if request.method == 'POST':
        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        
        # Store the generated keys in memory
        key_storage.append({"private_key": private_key, "public_key": public_key})
        
        return render_template('generate_keys.html', private_key=private_key, public_key=public_key)
    return render_template('generate_keys.html')


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        data = request.json
        message = data.get('message')
        public_key_str = data.get('public_key')
        algorithm = data.get('algorithm')
        token = data.get('token')  # Optional token for extra encryption

        try:
            if algorithm == 'RSA':
                # RSA encryption
                public_key = RSA.import_key(public_key_str)
                cipher_rsa = PKCS1_OAEP.new(public_key)
                encrypted_message = cipher_rsa.encrypt(message.encode())
                encrypted_message_b64 = base64.b64encode(encrypted_message).decode()

            elif algorithm == 'AES':
                # AES encryption
                aes_key = get_random_bytes(16)  # AES key must be 16 bytes for AES-128
                cipher_aes = AES.new(aes_key, AES.MODE_EAX)
                ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
                encrypted_message_b64 = base64.b64encode(cipher_aes.nonce + tag + ciphertext).decode()

            # If a token is provided, append it to the encrypted message
            if token:
                encrypted_message_b64 += f"||{token}"

            return jsonify({"encrypted_message": encrypted_message_b64})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # Render encryption page with available public keys
    return render_template('encrypt.html', public_keys=[key['public_key'] for key in key_storage])

def get_private_keys():
    # Example list of private keys. Replace with your actual logic.
    return [
        '-----BEGIN PRIVATE KEY-----\nMIIE...your private key...\n-----END PRIVATE KEY-----', 
        '-----BEGIN PRIVATE KEY-----\nMIIE...another private key...\n-----END PRIVATE KEY-----'
    ]


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    # Handle POST request for decryption
    if request.method == 'POST':
        data = request.json
        encrypted_message_b64 = data.get('encrypted_message')
        private_key_str = data.get('private_key')

        try:
            # Import receiver's private key
            private_key = RSA.import_key(private_key_str)
            cipher_rsa = PKCS1_OAEP.new(private_key)

            # Decrypt the message
            encrypted_message = base64.b64decode(encrypted_message_b64)
            decrypted_message = cipher_rsa.decrypt(encrypted_message).decode()

            return jsonify({"decrypted_message": decrypted_message})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # For GET requests: Fetch the encrypted message and private keys (from storage or generated previously)
    encrypted_message = "EncryptedMessageWithToken||token123"  # Replace with actual encrypted message (with token)
    private_keys = get_private_keys()  # List of private keys

    return render_template('decrypt.html', encrypted_message=encrypted_message, private_keys=private_keys)

