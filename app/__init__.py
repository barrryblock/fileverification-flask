from flask import Flask, flash, request, jsonify, render_template
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from base64 import b64decode
import os
import time
import logging
from hurry.filesize import size
import jwt
import io
import base64
import uuid
import ssl
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

app = Flask(__name__)
registered_devices = {'1234', '2345'}

# Configure Azure Storage
AZURE_STORAGE_CONNECTION_STRING = "BlobEndpoint=https://flaskserver.blob.core.windows.net/;QueueEndpoint=https://flaskserver.queue.core.windows.net/;FileEndpoint=https://flaskserver.file.core.windows.net/;TableEndpoint=https://flaskserver.table.core.windows.net/;SharedAccessSignature=sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupiyx&se=2024-07-13T06:04:27Z&st=2024-07-12T22:04:27Z&spr=https&sig=zxjmkiljm2BzboTFRZEgGk%2Fdd4TVUof9upKheWxjLmI%3D"
AZURE_CONTAINER_NAME = "uploaded-files"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docs'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configure logging
logging.basicConfig(level=logging.INFO, filename="api.log",
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Load the public key from a file
def load_public_key():
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Verify the signature
def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception as e:
        logging.error(f"Verification failed: {e}")
        return False

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/api/files', methods=['GET'])
def list_files():
    filesInfos = []
    blob_list = container_client.list_blobs()
    for blob in blob_list:
        blob_client = container_client.get_blob_client(blob)
        blob_properties = blob_client.get_blob_properties()
        file_info = {
            "name": blob.name,
            "size": size(blob_properties.size),
            "date": blob_properties.last_modified.strftime('%a, %d %b %Y %H:%M:%S GMT'),
            "unix_time": time.mktime(blob_properties.last_modified.timetuple())
        }
        filesInfos.append(file_info)
    return jsonify(filesInfos)

@app.route('/api/files', methods=['POST'])
def upload_file():
    if 'file' not in request.files or 'deviceId' not in request.form:
        return jsonify({'status': 'error', 'detail': 'Missing file or deviceId'})

    device_id = request.form['deviceId']
    file = request.files['file']
    filename = secure_filename(file.filename)

    if device_id not in registered_devices:
        return jsonify({'status': 'error', 'detail': 'Unauthorized device'})

    if file.filename == '':
        flash('No selected file')
        return 'no selected file'

    if file and allowed_file(file.filename):
        blob_client = container_client.get_blob_client(filename)
        blob_client.upload_blob(file)
        return 'success!'

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    file_content = b64decode(data['file_content'])
    signed_data = b64decode(data['signed_data'])

    logging.info("Received request with file content and signed data.")

    public_key = load_public_key()
    is_verified = verify_signature(public_key, signed_data, file_content)

    if is_verified:
        # Save the file to Azure Blob Storage
        blob_name = "uploaded_file_" + str(uuid.uuid4())
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(file_content)
        logging.info("Signature verified and file saved to Azure Blob Storage successfully.")
        return jsonify({"message": "Signature verified and file saved successfully!"}), 200
    else:
        logging.warning("Signature verification failed.")
        return jsonify({"message": "Signature verification failed!"}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
