from azure.cosmos import CosmosClient, exceptions
from pymongo import MongoClient, errors
from azure.storage.blob import BlobServiceClient
from flask import Flask, abort, jsonify, request, redirect, flash, render_template
import os
from google.oauth2 import id_token
from google.auth.transport import requests
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import json
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING') # retrieve the connection string from the environment variable
container_name = "uploaded-files" # container name in which images will be store in the storage account
mongo_uri = os.getenv('AZURE_COSMOS_MONGO_URI')
database_name = 'DeviceDatabase'
collection_name = 'devices'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not connect_str:
    raise ValueError("AZURE_STORAGE_CONNECTION_STRING environment variable is not set.")
if not mongo_uri:
    raise ValueError("AZURE_COSMOS_MONGO_URI environment variable is not set.")

blob_service_client = BlobServiceClient.from_connection_string(conn_str=connect_str) # create a blob service client to interact with the storage account
try:
    container_client = blob_service_client.get_container_client(container=container_name) # get container client to interact with the container in which images will be stored
    container_client.get_container_properties() # get properties of the container to force exception to be thrown if container does not exist
except Exception as e:
    logger.error(f"Error: {e}")
    print("Creating container...")
    container_client = blob_service_client.create_container(container_name) # create a container in the storage account if it does not exist

mongo_client = MongoClient(mongo_uri)
database = mongo_client[database_name]
device_collection = database[collection_name]

@app.before_request
def validate_device():
    if request.path.startswith('/api') or request.path.startswith('/upload-photos') or request.path == '/':
        device_id = request.headers.get('deviceid')
        device_token = request.headers.get('deviceToken')

        if not device_id or not device_token:
            abort(401, 'Device authentication required.')

        device = device_collection.find_one({'deviceid': device_id})
        if not device or device['deviceToken'] != device_token or not device.get('attested', False):
            abort(403, 'Device not attested or invalid token.')

# Endpoint to register a device
@app.route("/register-device", methods=["POST"])
def register_device():
    device_id = request.json.get('deviceid')
    device_token = request.json.get('deviceToken')
    

    if not device_id or not device_token:
        abort(400, 'Device ID and token are required.')

    if device_collection.find_one({'deviceid': device_id}):
        abort(409, 'Device already registered.')

    device_collection.insert_one({'deviceid': device_id, 'deviceToken': device_token, 'attested': False})

    return jsonify({'message': 'Device registered successfully.'}), 201

# Endpoint to attest a device
@app.route("/attest-device", methods=["POST"])
def attest_device():
    device_id = request.headers.get('deviceid')
    device_token = request.headers.get('deviceToken')
    data = request.get_json()
    if not data or 'public_key' not in data:
        abort(400, 'Public key is required.')
    public_key = data['public_key']
    #public_key = request.json.get('public_key')

    if not device_id or not device_token:
        abort(400, 'Device ID and token are required.')

    device = device_collection.find_one({'deviceid': device_id})
    if device and device['deviceToken'] == device_token:
        device_collection.update_one(
            {'deviceid': device_id},
            {'$set': {'attested': True, 'publicKey': public_key}}
        )
        return jsonify({'message': 'Device attested successfully.'}), 200
    else:
        abort(403, 'Invalid device token or device not registered.')

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/api/files", methods=["GET"])
def get_files_json():
    blob_items = container_client.list_blobs()  # list all the blobs in the container
    files = []
   

    for blob in blob_items:
        blob_client = container_client.get_blob_client(blob=blob.name)  # get blob client to interact with the blob and get blob url
        blob_properties = blob_client.get_blob_properties() 
        files.append({
            "name": blob.name,
            "url": blob_client.url,
            "size": blob_properties.size,
            "last_modified": blob_properties.last_modified.isoformat()
        })

    return jsonify(files)

# Replace with your client ID
CLIENT_ID = "112966719495849603935.apps.googleusercontent.com"

def add_padding(public_key_str):
    # Ensure the public key string is properly padded
    return public_key_str.replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n").replace("-----END PUBLIC KEY-----", "\n-----END PUBLIC KEY-----\n")

def verify_signature(public_key_str, data, signature):
    device_id = request.headers.get('deviceid')
    device_token = request.headers.get('deviceToken')


    try:
        device = device_collection.find_one({'deviceid': device_id})
        if device and device['deviceToken'] == device_token:
            public_key_str = device.get('publicKey')
            logger.info(f"Public Key: {public_key_str}")
            logger.info(f"data: {data}")
            logger.info(f"signature: {signature}")
            print(f"Public Key: {public_key_str}")
            print(f"data: {data}")
            print(f"signature: {signature}")
            decoded_data = base64.b64decode(data)
            decoded_signature = base64.b64decode(signature)
            print(f"decoded data: {decoded_data}")
            print(f"decoded signature: {decoded_signature}")
        if not public_key_str:
            abort(403, 'Public key not found for device.')
        public_key = load_pem_public_key((add_padding(public_key_str.encode('utf-8'))))
        public_key.verify(
            base64.b64decode(signature),
            base64.b64decode(data),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")

        print(f"Signature verification failed: {e}")
        return False

@app.route('/api/challenge', methods=['GET'])
def get_challenge():
    challenge = os.urandom(32).hex()
    return jsonify({'challenge': challenge})

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if the request contains a file and signed data
    try:
        missing_fields = []
        if 'signed_challenge' not in request.form:
            missing_fields.append('signed_challenge')
        if 'public_key' not in request.form:
            missing_fields.append('public_key')
        # if 'encrypted_file_content' not in request.form:
        #     missing_fields.append('encrypted_file_content')
        # if 'signed_encrypted_content' not in request.form:
        #     missing_fields.append('signed_encrypted_content')
        if 'challenge' not in request.form:
            missing_fields.append('challenge')
        if missing_fields:
            received_params = {
                'form': request.form.to_dict()
            }
            error_message = f"Missing required fields or files: {missing_fields}. Received params: {received_params}"
            logger.error(f"Missing required fields or files: {missing_fields}. Received params: {received_params}")
            return jsonify({"error": error_message}), 400

        
        signed_challenge = request.form['signed_challenge']
        public_key = request.form['public_key']
        # encrypted_file_content = request.form['encrypted_file_content']
        # signed_encrypted_content = request.form['signed_encrypted_content']
        challenge = request.form['challenge']
        # file = request.files['file']
        print(f"Public key from API: {public_key}")

        if not verify_signature(public_key, challenge, signed_challenge):
                return jsonify({"message": "Invalid signed challenge"}), 400

            # Verify the signed encrypted file content
        # if not verify_signature(public_key, encrypted_file_content, signed_encrypted_content):
        #         return jsonify({"message": "Invalid signed encrypted file content"}), 400

        
        files = request.files.getlist('file')

        if not signed_challenge or not files:
            return jsonify({'error': 'Missing signed challenge or files'}), 400

        uploaded_files = []

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                try:
                    blob_client = blob_service_client.get_blob_client(container=container_name, blob=filename)
                    blob_client.upload_blob(file, overwrite=True)
                    uploaded_files.append(filename)
                    # Prepare the metadata to store in Mongo DB
                    file_metadata = {
                            "file": filename,
                            "signed_challenge": signed_challenge,
                            "challenge": challenge,
                            "blob_url": blob_client.url
                    }
                        
                    db = mongo_client["FileMatadata"]
                    collection = db["Metadata"]
                    try:
                        collection.insert_one(file_metadata)
                    except Exception as e:
                        logger.error(f"Error: {e}")
                        return jsonify({"error": str(e)}), 500
                except Exception as e:
                    print(f"Error uploading {filename}: {str(e)}")

                    return jsonify({'error': f'Failed to upload file {filename} to Azure Blob Storage'}), 500
            else:
                return jsonify({'error': 'Invalid file type. Only image files are allowed.'}), 400

        

        # # Store the encrypted file in Azure Blob Storage
        # blob_client = blob_service_client.get_blob_client(container=container_name, blob='encrypted_file.txt')
        # blob_client.upload_blob(encrypted_file_content, overwrite=True)
        
        

        return jsonify({"message": "Challenge verified and file stored successfully"}), 200
    except Exception as e:
        print(f"Error: {e}")
        logger.error(f"Error: {e}")
        return jsonify({"An error occured::": str(e)}), 500
    # # Verify the signed challenge
    # try:
    #     public_key.verify(
    #         base64.b64decode(signed_challenge.encode()),
    #         challenge.encode(),
    #         padding.PKCS1v15(),
    #         hashes.SHA256()
    #     )
    #     # Save the file to Azure Blob Storage
    #     blob_client = container_client.get_blob_client(file.filename)
    #     blob_client.upload_blob(file, overwrite=True)

@app.route('/verify', methods=['POST'])
def verify_integrity_token():
    token = request.json.get('token')

    if not token:
        return jsonify({'error': 'Token is missing'}), 400

    try:
        # Verify the integrity token
        id_info = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

        # The token is valid, proceed with your logic
        return jsonify({'status': 'success', 'data': id_info}), 200

    except ValueError as e:
        # Invalid token
        logger.error(f"Error: {e}")
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 400
    
#flask endpoint to upload a photo
@app.route("/upload-files", methods=["POST"])
def upload_files():
    filenames = ""

    for file in request.files.getlist("uploaded-files"):
        try:
            container_client.upload_blob(file.filename, file) # upload the file to the container using the filename as the blob name
            filenames += file.filename + "<br /> "
        except Exception as e:
            print(e)
            logger.error(f"Error: {e}")
            print("Ignoring duplicate filenames") # ignore duplicate filenames
        
    return redirect('/') 

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)

