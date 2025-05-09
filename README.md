# Secure API Project Documentation

This document provides a comprehensive guide for testing the Secure API project using Postman, verifying the MongoDB database with `mongosh`, and checking HashiCorp Vault via its UI and terminal commands. It includes step-by-step instructions for testing all endpoints and functionalities, expected inputs and outputs, and their meanings. Additionally, it covers the system architecture, encryption and hashing algorithms, database structure, key management, and the rationale behind tool and method choices.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Encryption and Hashing Algorithms](#encryption-and-hashing-algorithms)
3. [Database Structure](#database-structure)
4. [Key Management](#key-management)
5. [Tool and Method Selection Rationale](#tool-and-method-selection-rationale)
6. [Testing the API with Postman](#testing-the-api-with-postman)
   - [Prerequisites](#prerequisites)
   - [Testing User Registration](#testing-user-registration)
   - [Testing User Login](#testing-user-login)
   - [Testing OTP-based 2FA](#testing-otp-based-2fa)
   - [Testing Sensitive Data Management](#testing-sensitive-data-management)
   - [Testing Master Key Rotation](#testing-master-key-rotation)
7. [Database and Vault Verification](#database-and-vault-verification)
   - [MongoDB Verification](#mongodb-verification)
   - [Vault Verification](#vault-verification)

---

## System Architecture

The Secure API is built using FastAPI, a high-performance Python web framework, integrated with MongoDB for data storage and HashiCorp Vault for secure key management. The system is containerized with Docker, comprising three services:

- **API Service (`securerestapi-kms-app-1`)**: Manages user authentication, sensitive data operations, and key rotation. Runs on port `8000`.
- **MongoDB (`securerestapi-kms-mongo-1`)**: Stores user credentials and encrypted sensitive data. Runs on port `27017`.
- **Vault (`securerestapi-kms-vault-1`)**: Handles encryption keys securely. Runs on port `8200`.

Authentication is handled via JWT (JSON Web Tokens), with bcrypt for password hashing, AES-256-GCM for sensitive data encryption, and TOTP (Time-based One-Time Passwords) for two-factor authentication (2FA).

---

## Encryption and Hashing Algorithms

- **Password Hashing**: 
  - Algorithm: Bcrypt with a unique salt per user and a global pepper (from `.env`).
  - Purpose: Ensures passwords are securely stored and resistant to brute-force attacks.
- **Sensitive Data Encryption**: 
  - Algorithm: AES-256-GCM.
  - Purpose: Provides authenticated encryption for confidentiality and integrity of sensitive data (e.g., card numbers).
- **Key Encryption**: 
  - Algorithm: AES-256-GCM.
  - Purpose: Encrypts user-specific keys with a master key stored in Vault.
- **JWT Signing**: 
  - Algorithm: HS256 (HMAC with SHA-256).
  - Purpose: Secures JWT tokens for user authentication.

---

## Database Structure

MongoDB uses two collections:

1. **users**:
   - `_id`: ObjectId (auto-generated)
   - `username`: String (unique identifier)
   - `email`: String (user’s email)
   - `hashed_password`: String (bcrypt-hashed password with salt and pepper)
   - `salt`: String (unique per user, hex-encoded)
   - `failed_attempts`: Integer (tracks login failures)
   - `last_failed_attempt_time`: Date (timestamp of last failed attempt)
   - `totp_secret`: String (base32-encoded TOTP secret for 2FA)
   - `two_factor_enabled`: Boolean (indicates if 2FA is enabled)

2. **sensitive_data**:
   - `_id`: ObjectId (auto-generated)
   - `user_id`: ObjectId (references `users._id`)
   - `data_type`: String (e.g., "card_number")
   - `encrypted_value`: String (hex-encoded encrypted data)

---

## Key Management

- **Master Key**: 
  - Stored in Vault at `secret/master_key`.
  - Used to encrypt user-specific keys with AES-256-GCM.
- **User Encryption Keys**: 
  - Generated as AES-256 keys during user registration.
  - Encrypted with the master key and stored in Vault at `secret/user_keys/<username>` with a nonce.
- **Key Rotation**: 
  - The `/rotate-master-key` endpoint generates a new master key and updates Vault.

---

## Tool and Method Selection Rationale

- **FastAPI**: Chosen for its asynchronous capabilities, performance, and automatic OpenAPI documentation.
- **MongoDB**: Selected for its NoSQL flexibility and seamless integration with Python via Motor.
- **Vault**: Provides secure, centralized key management with robust access controls.
- **Bcrypt**: Industry-standard for password hashing, resistant to rainbow table attacks.
- **AES-256-GCM**: Ensures both confidentiality and integrity with authenticated encryption.
- **Docker**: Ensures consistent deployment across environments and simplifies service orchestration.

---

## Testing the API with Postman

### Prerequisites

1. **Docker Containers**: Ensure all services are running:
   - `securerestapi-kms-app-1` (API, port `8000`)
   - `securerestapi-kms-mongo-1` (MongoDB, port `27017`)
   - `securerestapi-kms-vault-1` (Vault, port `8200`)
   - Check with: `docker ps`
2. **Postman**: Installed and configured to send requests to `http://localhost:8000`.
3. **Environment Variables**: Verify `.env` is set with `VAULT_TOKEN=myroot`, SMTP credentials, etc.

### Testing User Registration

**Step 1: Register a new user**

- **Endpoint**: `POST http://localhost:8000/register`
- **Body** (raw JSON):
  ```json
  {
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test123!"
  }
  ```
- **Expected Response**: Status `200 OK`
  ```json
  {
    "message": "User registered successfully"
  }
  ```
- **Meaning**: User is created in MongoDB, and their encryption key is stored in Vault.

### Testing User Login

**Step 2: Login with correct credentials**

- **Endpoint**: `POST http://localhost:8000/login`
- **Body** (raw JSON):
  ```json
  {
    "username": "testuser",
    "password": "Test123!"
  }
  ```
- **Expected Response**: Status `200 OK`
  ```json
  {
    "access_token": "<JWT_TOKEN>",
    "token_type": "bearer"
  }
  ```
- **Meaning**: Successful authentication returns a JWT token valid for 1 hour.

**Step 3: Login with incorrect password (5 times)**

- **Endpoint**: `POST http://localhost:8000/login`
- **Body** (raw JSON):
  ```json
  {
    "username": "testuser",
    "password": "WrongPass"
  }
  ```
- **Expected Response (after 5 attempts)**: Status `400 Bad Request`
  ```json
  {
    "detail": "Too many failed attempts. Try again later."
  }
  ```
- **Meaning**: After 5 failed attempts, the account is locked for 15 minutes.

### Testing OTP-based 2FA

**Step 4: Send OTP**

- **Endpoint**: `POST http://localhost:8000/send-otp`
- **Body** (raw JSON):
  ```json
  {
    "username": "testuser"
  }
  ```
- **Expected Response**: Status `200 OK`
  ```json
  {
    "message": "OTP sent to your email"
  }
  ```
- **Meaning**: A TOTP code is generated and emailed to `test@example.com`.

**Step 5: Verify OTP**

- **Endpoint**: `POST http://localhost:8000/verify-otp`
- **Body** (raw JSON):
  ```json
  {
    "username": "testuser",
    "otp": "<OTP_CODE>"
  }
  ```
- **Expected Response**: Status `200 OK`
  ```json
  {
    "access_token": "<JWT_TOKEN>",
    "token_type": "bearer"
  }
  ```
- **Meaning**: OTP is valid, 2FA is enabled, and a JWT token is returned.

### Testing Sensitive Data Management

**Step 6: Store sensitive data**

- **Endpoint**: `POST http://localhost:8000/sensitive-data`
- **Headers**: `Authorization: Bearer <JWT_TOKEN>`
- **Body** (raw JSON):
  ```json
  {
    "data_type": "card_number",
    "value": "1234567890123456"
  }
  ```
- **Expected Response**: Status `200 OK`
  ```json
  {
    "id": "<OBJECT_ID>",
    "data_type": "card_number",
    "value": "1234567890123456"
  }
  ```
- **Meaning**: Data is encrypted with the user’s key and stored in MongoDB.

**Step 7: Retrieve sensitive data**

- **Endpoint**: `GET http://localhost:8000/sensitive-data`
- **Headers**: `Authorization: Bearer <JWT_TOKEN>`
- **Expected Response**: Status `200 OK`
  ```json
  [
    {
      "id": "<OBJECT_ID>",
      "data_type": "card_number",
      "value": "1234567890123456"
    }
  ]
  ```
- **Meaning**: Encrypted data is retrieved, decrypted, and returned.

**Step 8: Update sensitive data**

- **Endpoint**: `PUT http://localhost:8000/sensitive-data/<OBJECT_ID>`
- **Headers**: `Authorization: Bearer <JWT_TOKEN>`
- **Body** (raw JSON):
  ```json
  {
    "data_type": "card_number",
    "value": "6543210987654321"
  }
  ```
- **Expected Response**: Status `200 OK`
  ```json
  {
    "id": "<OBJECT_ID>",
    "data_type": "card_number",
    "value": "6543210987654321"
  }
  ```
- **Meaning**: Data is updated, re-encrypted, and stored.

**Step 9: Delete sensitive data**

- **Endpoint**: `DELETE http://localhost:8000/sensitive-data/<OBJECT_ID>`
- **Headers**: `Authorization: Bearer <JWT_TOKEN>`
- **Expected Response**: Status `200 OK`
  ```json
  {
    "message": "Data deleted successfully"
  }
  ```
- **Meaning**: Data is removed from MongoDB.

### Testing Master Key Rotation

**Step 10: Rotate the master key**

- **Endpoint**: `POST http://localhost:8000/rotate-master-key`
- **Headers**: `Authorization: Bearer <JWT_TOKEN>`
- **Expected Response**: Status `200 OK`
  ```json
  {
    "message": "Master key rotated successfully"
  }
  ```
- **Meaning**: A new master key is generated and stored in Vault.

---

## Database and Vault Verification

### MongoDB Verification

1. **Access MongoDB Container**:
   ```bash
   docker exec -it securerestapi-kms-mongo-1 mongosh
   ```
2. **Switch to Database**:
   ```javascript
   use secure_api
   ```
3. **Check Users Collection**:
   ```javascript
   db.users.find().pretty()
   ```
   - **Expected Output**: Documents with fields like `username`, `hashed_password`, `salt`, `totp_secret`, etc.
   - **Meaning**: Verifies user registration and 2FA status.
4. **Check Sensitive Data Collection**:
   ```javascript
   db.sensitive_data.find().pretty()
   ```
   - **Expected Output**: Documents with `user_id`, `data_type`, and `encrypted_value` (hex string).
   - **Meaning**: Confirms encrypted data storage.

### Vault Verification

1. **Via Vault UI**:
   - Open `http://localhost:8200`.
   - Log in with token `myroot` (from `.env`).
   - Navigate to `secret/master_key`:
     - **Expected Output**: Key stored as a hex string.
     - **Meaning**: Master key is present.
   - Navigate to `secret/user_keys/testuser`:
     - **Expected Output**: Encrypted key and nonce as hex strings.
     - **Meaning**: User key is securely stored.

2. **Via Terminal**:
   - Access Vault container:
     ```bash
     docker exec -it securerestapi-kms-vault-1 /bin/sh
     ```
   - List secrets:
     ```bash
     vault kv list secret
     ```
     - **Expected Output**: `master_key`, `user_keys/testuser`, etc.
     - **Meaning**: Confirms stored keys.
   - Retrieve user key:
     ```bash
     vault kv get secret/user_keys/testuser
     ```
     - **Expected Output**: JSON with `key` and `nonce` fields.
     - **Meaning**: Verifies key storage details.

---

This guide ensures a thorough test of the Secure API project, validating functionality, security, and integration with MongoDB and Vault.