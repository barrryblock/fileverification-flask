
# Flask Device Attestation and File Upload Service

## Overview

This Flask application is designed to handle device registration, attestation, and secure file uploads to Azure Blob Storage. The service validates devices before processing requests and verifies the integrity of uploaded files using cryptographic signatures. The application also interacts with a MongoDB database (hosted on Azure Cosmos DB) to store device and file metadata.

## Features

- **Device Registration:** Devices can be registered with a unique `deviceid` and `deviceToken`.
- **Device Attestation:** Devices are attested by uploading a public key, ensuring secure communication.
- **File Upload:** Devices can upload files to Azure Blob Storage after a successful challenge-response verification.
- **Google Play Integrity Token Verification:** Verifies integrity tokens using Google's OAuth2 token verification.
- **Blob Storage Interaction:** Lists, uploads, and retrieves files stored in Azure Blob Storage.
- **MongoDB Interaction:** Stores metadata for registered devices and uploaded files in MongoDB.

## Prerequisites

Before running the application, ensure you have the following:

- Python 3.7+
- Azure Storage Account with a Blob Container
- MongoDB instance (Azure Cosmos DB with MongoDB API)
- Flask installed (`pip install flask`)
- Azure and MongoDB Python SDKs installed:
  ```sh
  pip install azure-cosmos azure-storage-blob pymongo cryptography
  ```

## Environment Variables

Set the following environment variables in your environment or in a `.env` file:

- `AZURE_STORAGE_CONNECTION_STRING`: Connection string for your Azure Storage account.
- `AZURE_COSMOS_MONGO_URI`: MongoDB connection URI (Azure Cosmos DB).

## Setup

1. **Clone the repository:**

   ```sh
   git clone https://github.com/your-repo/flask-device-attestation.git
   cd flask-device-attestation
   ```

2. **Install the dependencies:**

   ```sh
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**

   ```sh
   export AZURE_STORAGE_CONNECTION_STRING="your-azure-storage-connection-string"
   export AZURE_COSMOS_MONGO_URI="your-mongo-uri"
   ```

4. **Run the application:**

   ```sh
   python app.py
   ```

   The application will start on `http://0.0.0.0:5000`.

## API Endpoints

### 1. Register Device

- **Endpoint:** `/register-device`
- **Method:** POST
- **Description:** Registers a new device.
- **Payload:**
  ```json
  {
    "deviceid": "your-device-id",
    "deviceToken": "your-device-token"
  }
  ```
- **Response:**
  - `201`: Device registered successfully.
  - `400`: Missing device ID or token.
  - `409`: Device already registered.

### 2. Attest Device

- **Endpoint:** `/attest-device`
- **Method:** POST
- **Description:** Attests a registered device by uploading its public key.
- **Headers:**
  - `deviceid`: The device ID.
  - `deviceToken`: The device token.
- **Payload:**
  ```json
  {
    "public_key": "your-public-key"
  }
  ```
- **Response:**
  - `200`: Device attested successfully.
  - `403`: Invalid device token or device not registered.

### 3. Get Files

- **Endpoint:** `/api/files`
- **Method:** GET
- **Description:** Retrieves a list of files stored in the Azure Blob Storage container.
- **Response:**
  - `200`: List of files with metadata.

### 4. Upload File

- **Endpoint:** `/upload-file`
- **Method:** POST
- **Description:** Uploads a file to Azure Blob Storage after verifying the signed challenge.
- **Payload:**
  - `signed_challenge`: The signed challenge response.
  - `public_key`: The device's public key.
  - `challenge`: The challenge string.
  - `file`: The file to be uploaded.
- **Response:**
  - `200`: File uploaded successfully.
  - `400`: Invalid signed challenge or file type.

### 5. Verify Integrity Token

- **Endpoint:** `/verify`
- **Method:** POST
- **Description:** Verifies the integrity token using Google Play Integrity API.
- **Payload:**
  ```json
  {
    "token": "your-integrity-token"
  }
  ```
- **Response:**
  - `200`: Token is valid.
  - `400`: Invalid token or error message.

### 6. Get Challenge

- **Endpoint:** `/api/challenge`
- **Method:** GET
- **Description:** Generates and returns a challenge (nonce) for the device.
- **Response:**
  - `200`: Challenge generated successfully.

## Logging

The application logs all activities, including errors and important operations, using Python's built-in `logging` module. Logs are outputted to the console.

## Error Handling

The application handles errors gracefully and returns appropriate HTTP status codes with descriptive error messages for all operations.

## Security

- **Device Authentication:** Devices are authenticated using a `deviceid` and `deviceToken`.
- **Signature Verification:** Ensures that uploaded files and requests are from authenticated and attested devices.
- **Google Play Integrity:** Verifies the integrity of requests using Google's Play Integrity API.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
