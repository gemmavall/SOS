from flask import Flask, jsonify, request
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os
import requests



app = Flask(__name__)
CORS(app)

#getting the key from the Luxquanta devices in the E lab via ETSI014

# def get_key():
#     # Define the URL
#     url = "https://192.36.164.181/api/v1/keys/bob_client1/enc_keys?number=1&size=256"

#     # Define the paths to the certificates and key
#     ca_cert = "rootCA_auth.crt"
#     client_cert = "alice_client1.crt"
#     client_key = "alice_client1.key"

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



# Dummy function to simulate key fetching
# def get_key():
#     # Simulating fetching a key
#     key = os.urandom(16)  # 128-bit AES key
#     key_id = "dummy-key-id"
#     return {"key": base64.b64encode(key).decode('utf-8'), "key_ID": key_id}


# get_key code to run the app in my local computer

def get_key():
    return {
        'key_ID': 'dummy_key_id',
        'key': base64.b64encode(b'16_byte_test_key').decode('utf-8')
    }

#the route specifies that the code under will be on a server and we will use the post method to get the information from that server. the routes are useful when we need to run code in two different comptuers, for example.
#then the server functionality allows the two different computers to find each other. 

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    input_data = request.get_json()
    plaintext = input_data['message']

    # Fetch encryption key
    key_data = get_key()
    key = base64.b64decode(key_data['key'])
    key_id = key_data['key_ID']

    # Encrypt the message
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

    return jsonify({
        "encrypted_message": base64.b64encode(ciphertext).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "key_id": key_id
    }), 200

#I believe this is also code related to having created a server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
