from flask import Flask, jsonify, request
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import os
import requests

app = Flask(__name__)
CORS(app)

# Dummy function to simulate key fetching by key ID
# def get_key_using_keyid(key_id):
#     # Simulating fetching a key
#     key = base64.b64encode(os.urandom(16)).decode('utf-8')  # Match encryption key structure
#     return {"key": key}

#code needed for running the app in the lab with the luxquanata devices

# def get_key_using_keyid(KEY_ID):
#     # Define the URL
#     url = "https://192.36.164.182/api/v1/keys/alice_client1/dec_keys?key_ID="+KEY_ID

#     # Define the paths to the certificates and key
#     ca_cert = "rootCA_auth.crt"
#     client_cert = "bob_client1.crt"
#     client_key = "bob_client1.key"

#     # Set the headers
#     headers = {
#         "Content-Type": "application/json"
#     }

#     # Make the request with the certificates and key
#     response = requests.get(
#         url,
#         headers=headers,
#         cert=(client_cert, client_key),
#         verify=ca_cert
#     )

#     result = response.json()
#     return result['keys'][0]

#code neded to run the app on my local computer

def get_key_using_keyid(key_id):
    # Return a mock response for testing
    return {
        'key': base64.b64encode(b'16_byte_test_key').decode('utf-8')
    }

#we emulate a server with the route and we use post to request information and process the code below
@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    input_data = request.get_json()
    encrypted_message = base64.b64decode(input_data['encrypted_message'])
    iv = base64.b64decode(input_data['iv'])
    key_id = input_data['key_id']

    # Fetch decryption key using key_id
    key_data = get_key_using_keyid(key_id)
    key = base64.b64decode(key_data['key'])

    # Decrypt the message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    return jsonify({"message": decrypted_message.decode('utf-8')}), 200

#this defines where the server is hosted. 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
