# Secure RESTful API with Encrypted Data Storage and Key Management

This project implements a secure RESTful API designed to handle user authentication, sensitive data management, and key rotation while ensuring the confidentiality, integrity, and security of data during transmission and storage. Sensitive information is encrypted before being stored, and encryption keys are managed securely using HashiCorp Vault. The API is built with FastAPI, uses MongoDB for data storage, and is orchestrated with Docker Compose.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Cryptographic Algorithms and Hashing](#cryptographic-algorithms-and-hashing)
3. [Database Structure](#database-structure)
4. [Key Management](#key-management)
5. [Tool and Method Selection](#tool-and-method-selection)
6. [Setup and Testing Instructions](#setup-and-testing-instructions)
   - [Prerequisites](#prerequisites)
   - [Step-by-Step Setup](#step-by-step-setup)
   - [Testing with Postman](#testing-with-postman)
   - [Checking the Database](#checking-the-database)
   - [Vault UI Verification](#vault-ui-verification)
7. [Conclusion](#conclusion)

---

## Architecture Overview

The system is composed of three core components orchestrated by Docker Compose:

- **FastAPI Application**:
  - Built with FastAPI, a high-performance, asynchronous Python web framework.
  - Handles HTTP requests and responses for user registration, login, sensitive data operations, and key rotation.
  - Implements JWT-based authentication for secure user sessions.
  - Encrypts and decrypts sensitive data using user-specific keys retrieved from Vault.

- **MongoDB**:
  - A NoSQL database used to store user credentials and encrypted sensitive data.
  - Employs two collections: `users` for authentication data and `sensitive_data` for encrypted user information.
  - Integrated asynchronously with FastAPI via the `motor` library.

- **HashiCorp Vault**:
  - Acts as a secure key management system (KMS).
  - Stores the master encryption key and user-specific encryption keys, ensuring they are isolated from the application and database.
  - Provides key generation, storage, and rotation capabilities.

**Interaction**:
- The FastAPI application authenticates users, retrieves encryption keys from Vault, and stores encrypted data in MongoDB.
- Docker Compose ensures seamless deployment and interaction between these services, providing a consistent environment.

This architecture ensures that sensitive data is encrypted at rest and in transit, with keys managed securely outside the application logic.

---

## Cryptographic Algorithms and Hashing

The project employs robust, industry-standard cryptographic techniques:

- **Password Hashing**:
  - **Algorithm**: `bcrypt` with a work factor of 12 for computational resistance to brute-force attacks.
  - **Salt**: A unique 16-byte salt generated per user using `secrets.token_hex(16)` to prevent rainbow table attacks.
  - **Pepper**: A global secret (`PEPPER`) stored in the `.env` file, appended to passwords before hashing for an additional layer of security.
  - **Storage**: Only the resulting hash is stored in the `hashed_password` field of the `users` collection.

- **Data Encryption**:
  - **Algorithm**: AES-256-GCM, a symmetric encryption standard with authenticated encryption.
  - **Key**: Each user has a unique 256-bit encryption key, generated during registration and encrypted with the master key.
  - **Nonce**: A unique 12-byte nonce generated per encryption operation using `secrets.token_bytes(12)` to ensure ciphertext uniqueness.
  - **Implementation**: Provided by the `cryptography` library’s `AESGCM` module.

- **Key Management**:
  - **Master Key**: A 256-bit AES key stored in Vault at `kv/master_key`, used to encrypt user-specific keys.
  - **User Keys**: Encrypted with the master key using AES-256-GCM and stored in Vault at `kv/user_keys/<username>` with associated nonces.

- **JWT Signing**:
  - **Algorithm**: HS256 (HMAC with SHA-256).
  - **Secret**: A securely generated `JWT_SECRET` stored in the `.env` file.
  - **Expiration**: Tokens expire after 1 hour, enforced by the `exp` claim.

These choices ensure passwords are irretrievable, sensitive data is securely encrypted, and authentication tokens are tamper-proof.

---

## Database Structure

The MongoDB database (`secure_api`) is structured with two collections:

- **Users Collection (`users`)**:
  - `_id`: ObjectId (auto-generated unique identifier).
  - `username`: String (unique, user-provided identifier).
  - `email`: String (user’s email for OTP-based 2FA).
  - `hashed_password`: String (bcrypt-hashed password with salt and pepper).
  - `salt`: String (unique 16-byte hex string for password hashing).
  - `failed_attempts`: Integer (tracks consecutive failed login attempts, max 5 before lockout).
  - `last_failed_attempt_time`: Date (timestamp of the last failed attempt, resets after 15 minutes).
  - `totp_secret`: String (base32 secret for TOTP-based 2FA).
  - `two_factor_enabled`: Boolean (indicates if 2FA is enabled).

- **Sensitive Data Collection (`sensitive_data`)**:
  - `_id`: ObjectId (auto-generated unique identifier).
  - `user_id`: ObjectId (foreign key referencing the user’s `_id` in `users`).
  - `data_type`: String (e.g., `"card_number"`, describes the type of sensitive data).
  - `encrypted_value`: String (hex-encoded encrypted data, including nonce and ciphertext).

This structure separates authentication data from sensitive data, linking them via `user_id`, and ensures that sensitive data is stored in an encrypted form.

---

## Key Management

The key management system (KMS) is implemented using HashiCorp Vault and follows these principles:

- **Master Key**:
  - A 256-bit AES key stored at `kv/master_key` in Vault.
  - Generated on first use if not present, using `AESGCM.generate_key(bit_length=256)`.
  - Used to encrypt and decrypt user-specific keys.

- **User Encryption Keys**:
  - A unique 256-bit AES key is generated for each user during registration via `generate_encryption_key()`.
  - Encrypted with the master key using AES-256-GCM and stored in Vault at `kv/user_keys/<username>` with a nonce.
  - Retrieved and decrypted only when needed for data encryption/decryption.

- **Key Rotation**:
  - The `/rotate-master-key` endpoint generates a new master key and re-encrypts all user keys.
  - Process:
    1. Retrieve the old master key.
    2. Generate a new 256-bit master key.
    3. For each user, decrypt their key with the old master key and re-encrypt with the new one.
    4. Update the master key in Vault.
  - Ensures continuity without requiring re-encryption of stored data.

This design ensures keys are securely stored, managed, and rotated, minimizing exposure risks even in case of database compromise.

---

## Tool and Method Selection

The following tools and methods were selected for their strengths:

- **FastAPI**:
  - **Why**: High-performance, asynchronous framework with automatic OpenAPI documentation and Pydantic validation.
  - **Benefit**: Simplifies API development and ensures type safety and input validation.

- **MongoDB**:
  - **Why**: Flexible NoSQL database supporting dynamic schemas and efficient scaling.
  - **Benefit**: Ideal for storing varied sensitive data types and integrates seamlessly with Python via `motor`.

- **HashiCorp Vault**:
  - **Why**: Industry-standard solution for secrets and key management.
  - **Benefit**: Provides secure storage, access control, and key rotation, isolating keys from the application.

- **Docker Compose**:
  - **Why**: Simplifies multi-container application deployment.
  - **Benefit**: Ensures consistent environments and easy setup across development and production.

- **Cryptography Library**:
  - **Why**: Provides secure AES-256-GCM implementation.
  - **Benefit**: Trusted, well-tested cryptographic primitives.

These tools collectively deliver a secure, scalable, and developer-friendly solution.

---

## Setup and Testing Instructions

### Prerequisites

- **Docker**: Required to build and run the application containers.
- **Docker Compose**: Needed to orchestrate the services.
- **Postman**: Used for testing API endpoints.
- **Web Browser**: For accessing the Vault UI.
- **Terminal**: For interacting with the MongoDB shell.

### Step-by-Step Setup

1. **Clone the Repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Configure Environment Variables**:
   - Create a `.env` file in the project root with the following:
     ```
     MONGODB_URL=mongodb://mongo:27017
     DB_NAME=secure_api
     JWT_SECRET=<secure_random_string>
     PEPPER=<secure_random_string>
     VAULT_TOKEN=<vault_token>
     SMTP_SERVER=smtp.gmail.com
     SMTP_PORT=587
     SMTP_USERNAME=<your_smtp_username>
     SMTP_PASSWORD=<your_smtp_password>
     EMAIL_FROM=<your_email>
     ```
   - Replace placeholders:
     - `JWT_SECRET`: Generate with `openssl rand -base64 32`.
     - `PEPPER`: Generate with `openssl rand -base64 16`.
     - `VAULT_TOKEN`: Use a secure token (e.g., `myroot` for development).
     - SMTP fields: Use a valid email service account (e.g., Gmail with an App Password).

3. **Build and Run the Application**:
   ```bash
   docker-compose up --build
   ```
   - Builds the FastAPI app, MongoDB, and Vault containers.
   - API runs at `http://localhost:8000`.
   - Vault UI is accessible at `http://localhost:8200`.

4. **Verify Services**:
   - Check Docker containers:
     ```bash
     docker ps
     ```
   - Ensure `app`, `mongo`, and `vault` are running.

### Testing with Postman

Use Postman to test all endpoints. Save the `access_token` from login for authenticated requests.

1. **Register a User**:
   - **Method**: POST
   - **URL**: `http://localhost:8000/register`
   - **Body** (raw JSON):
     ```json
     {
       "username": "testuser",
       "email": "test@example.com",
       "password": "StrongP@ssw0rd1!"
     }
     ```
   - **Expected Response** (200 OK):
     ```json
     {"message": "User registered successfully"}
     ```
   - **Notes**: Password must be ≥8 characters, with uppercase, digit, and special character.

2. **Login**:
   - **Method**: POST
   - **URL**: `http://localhost:8000/login`
   - **Body** (raw JSON):
     ```json
     {
       "username": "testuser",
       "password": "StrongP@ssw0rd1!"
     }
     ```
   - **Expected Response** (200 OK):
     ```json
     {
       "access_token": "<token>",
       "token_type": "bearer"
     }
     ```
   - **Notes**: After 5 failed attempts, login is locked for 15 minutes.

3. **Store Sensitive Data**:
   - **Method**: POST
   - **URL**: `http://localhost:8000/sensitive-data`
   - **Headers**: `Authorization: Bearer <access_token>`
   - **Body** (raw JSON):
     ```json
     {
       "data_type": "card_number",
       "value": "1234567812345678"
     }
     ```
   - **Expected Response** (200 OK):
     ```json
     {
       "id": "<data_id>",
       "data_type": "card_number",
       "value": "1234567812345678"
     }
     ```
   - **Notes**: Card numbers must be 16 digits.

4. **Retrieve Sensitive Data**:
   - **Method**: GET
   - **URL**: `http://localhost:8000/sensitive-data`
   - **Headers**: `Authorization: Bearer <access_token>`
   - **Expected Response** (200 OK):
     ```json
     [
       {
         "id": "<data_id>",
         "data_type": "card_number",
         "value": "1234567812345678"
       }
     ]
     ```

5. **Update Sensitive Data**:
   - **Method**: PUT
   - **URL**: `http://localhost:8000/sensitive-data/<data_id>`
   - **Headers**: `Authorization: Bearer <access_token>`
   - **Body** (raw JSON):
     ```json
     {
       "data_type": "card_number",
       "value": "8765432187654321"
     }
     ```
   - **Expected Response** (200 OK):
     ```json
     {
       "id": "<data_id>",
       "data_type": "card_number",
       "value": "8765432187654321"
     }
     ```

6. **Delete Sensitive Data**:
   - **Method**: DELETE
   - **URL**: `http://localhost:8000/sensitive-data/<data_id>`
   - **Headers**: `Authorization: Bearer <access_token>`
   - **Expected Response** (200 OK):
     ```json
     {"message": "Data deleted successfully"}
     ```

7. **Rotate Master Key**:
   - **Method**: POST
   - **URL**: `http://localhost:8000/rotate-master-key`
   - **Headers**: `Authorization: Bearer <access_token>`
   - **Expected Response** (200 OK):
     ```json
     {"message": "Master key rotated successfully"}
     ```
   - **Notes**: Verifies key rotation without data re-encryption.

8. **Enable 2FA**:
   - **Step 1: Send OTP**:
     - **Method**: POST
     - **URL**: `http://localhost:8000/send-otp`
     - **Body** (raw JSON):
       ```json
       {
         "username": "testuser"
       }
       ```
     - **Expected Response** (200 OK):
       ```json
       {"message": "OTP sent to your email"}
       ```
     - **Notes**: Check the email for the 6-digit OTP.
   - **Step 2: Verify OTP**:
     - **Method**: POST
     - **URL**: `http://localhost:8000/verify-otp`
     - **Body** (raw JSON):
       ```json
       {
         "username": "testuser",
         "otp": "<otp_code>"
       }
       ```
     - **Expected Response** (200 OK):
       ```json
       {
         "access_token": "<token>",
         "token_type": "bearer"
       }
       ```
     - **Notes**: Enables 2FA for subsequent logins.

### Checking the Database

Access the MongoDB shell to verify data:
```bash
docker exec -it securerestapi-kms-mongo-1 mongosh
use secure_api
```

- **Users Collection**:
  ```bash
  db.users.find().pretty()
  ```
  - Check: `hashed_password` is a bcrypt hash, `salt` is unique, `totp_secret` is present.

- **Sensitive Data Collection**:
  ```bash
  db.sensitive_data.find().pretty()
  ```
  - Check: `encrypted_value` is a hex string, not plain text.

### Vault UI Verification

- Open `http://localhost:8200` in a browser.
- Log in with the `VAULT_TOKEN` from `.env` (e.g., `myroot`).
- Navigate to:
  - `kv/master_key`: Verify the master key exists as a hex string.
  - `kv/user_keys/testuser`: Confirm the encrypted user key and nonce are stored.

---

## Conclusion

This project delivers a secure, production-ready RESTful API that meets all specified requirements. It provides robust user authentication with JWT and 2FA, encrypted storage of sensitive data using AES-256-GCM, and secure key management with HashiCorp Vault. The use of FastAPI, MongoDB, and Docker Compose ensures scalability, maintainability, and ease of deployment. The implementation adheres to security best practices, making it suitable for environments where data protection is paramount.