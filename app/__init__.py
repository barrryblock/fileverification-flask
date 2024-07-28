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

app = Flask(__name__)


connect_str = os.getenv('AZURE_STORAGE_CONNECTION_STRING') # retrieve the connection string from the environment variable
container_name = "uploaded-files" # container name in which images will be store in the storage account
mongo_uri = os.getenv('AZURE_COSMOS_MONGO_URI')
database_name = 'DeviceDatabase'
collection_name = 'devices'

if not connect_str:
    raise ValueError("AZURE_STORAGE_CONNECTION_STRING environment variable is not set.")
if not mongo_uri:
    raise ValueError("AZURE_COSMOS_MONGO_URI environment variable is not set.")

blob_service_client = BlobServiceClient.from_connection_string(conn_str=connect_str) # create a blob service client to interact with the storage account
try:
    container_client = blob_service_client.get_container_client(container=container_name) # get container client to interact with the container in which images will be stored
    container_client.get_container_properties() # get properties of the container to force exception to be thrown if container does not exist
except Exception as e:
    print(e)
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
    device_id = request.json.get('deviceId')
    device_token = request.json.get('deviceToken')

    if not device_id or not device_token:
        abort(400, 'Device ID and token are required.')

    if device_collection.find_one({'deviceId': device_id}):
        abort(409, 'Device already registered.')

    device_collection.insert_one({'deviceId': device_id, 'deviceToken': device_token, 'attested': False})

    return jsonify({'message': 'Device registered successfully.'}), 201

# Endpoint to attest a device
@app.route("/attest-device", methods=["POST"])
def attest_device():
    device_id = request.json.get('deviceId')
    device_token = request.json.get('deviceToken')

    if not device_id or not device_token:
        abort(400, 'Device ID and token are required.')

    device = device_collection.find_one({'deviceId': device_id})
    if device and device['deviceToken'] == device_token:
        device_collection.update_one({'deviceId': device_id}, {'$set': {'attested': True}})
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

def verify_signature(public_key_str, data, signature):
    public_key = load_pem_public_key(base64.b64decode(public_key_str.encode()))
    try:
        public_key.verify(
            base64.b64decode(signature.encode()),
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
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
        if 'signed_challenge' not in request.form or 'public_key' not in request.form or 'encrypted_file_content' not in request.form or 'signed_encrypted_content' not in request.form or 'challenge' not in request.form:
            return jsonify({"error": "Missing required fields or files "+ str(request.form)}), 400

        
        signed_challenge = request.form['signed_challenge']
        public_key = request.form['public_key']
        encrypted_file_content = request.form['encrypted_file_content']
        signed_encrypted_content = request.form['signed_encrypted_content']
        challenge = request.form['challenge']
        # file = request.files['file']

        if not verify_signature(public_key, base64.b64decode(challenge.encode()), signed_challenge):
                return jsonify({"message": "Invalid signed challenge"}), 400

            # Verify the signed encrypted file content
        if not verify_signature(public_key, encrypted_file_content, signed_encrypted_content):
                return jsonify({"message": "Invalid signed encrypted file content"}), 400

        # Store the encrypted file in Azure Blob Storage
        blob_client = blob_service_client.get_blob_client(container=container_name, blob='encrypted_file.txt')
        blob_client.upload_blob(encrypted_file_content, overwrite=True)
        
        # Prepare the metadata to store in Mongo DB
        file_metadata = {
                "encrypted_content": encrypted_file_content,
                "signed_data": signed_encrypted_content,
                "blob_url": blob_client.url
        }
            
        db = mongo_client["FileMatadata"]
        collection = db["Metadata"]
        try:
            collection.insert_one(file_metadata)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        return jsonify({"message": "Challenge and file verified and stored successfully"}), 200
    except Exception as e:
        print(f"Error: {e}")
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
            print("Ignoring duplicate filenames") # ignore duplicate filenames
        
    return redirect('/') 

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)

