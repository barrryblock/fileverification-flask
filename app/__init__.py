from flask import Flask, flash,  request, jsonify , render_template
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

app = Flask(__name__)
registered_devices = {'1234','2345'}

UPLOAD_FOLDER = "uploaded_files"
LOG_FILE = "api.log"
ALLOWED_EXTENSIONS = { 'pdf', 'png', 'jpg', 'jpeg','doc', 'docs'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure the upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configure logging
logging.basicConfig(level=logging.INFO, filename=LOG_FILE,
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
    dirs = os.listdir(UPLOAD_FOLDER)
    for fileName in dirs:
        path = UPLOAD_FOLDER+'\\'+fileName
        fileSize = size(os.path.getsize(path))
        fileDateUnix = os.path.getmtime(path)
        fileDate = time.ctime(fileDateUnix)
        fileInfo = {"name": fileName, "size": fileSize,
                    "date": fileDate, "unix_time": fileDateUnix}
        filesInfos.append(fileInfo)
    return jsonify(filesInfos)

@app.route('/api/files', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files or 'deviceId' not in request.form:
            return jsonify({'status': 'error', 'detail': 'Missing file or deviceId'})

        device_id = request.form['deviceId']
        file = request.files['file']
        filename = secure_filename(file.filename)

        if device_id not in registered_devices:
            return jsonify({'status': 'error', 'detail': 'Unauthorized device'})
        
        if 'file' not in request.files:
            flash('No file part')
            return 'no file part'
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return 'no selected file'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
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
        # Save the file to the upload directory
        file_path = os.path.join(UPLOAD_FOLDER, "uploaded_file")
        with open(file_path, "wb") as f:
            f.write(file_content)
        logging.info("Signature verified and file saved successfully.")
        return jsonify({"message": "Signature verified and file saved successfully!"}), 200
    else:
        logging.warning("Signature verification failed.")
        return jsonify({"message": "Signature verification failed!"}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
