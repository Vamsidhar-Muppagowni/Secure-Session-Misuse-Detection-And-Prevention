# 🛡️ Secure Session & File Storage Lab

A secure web application demonstrating advanced authentication, session management, and secure file handling practices. This project uses **MongoDB Atlas** for cloud storage and implements strict security controls like **MFA**, **Single Session Enforcement**, and **File Encryption**.

## 🚀 Key Features

### 1. Advanced Authentication
*   **Email Verification**: Uses strict Email OTP verification during registration (via Nodemailer).
*   **Two-Factor Authentication (2FA)**: Time-based OTP (TOTP) using Google Authenticator (via Speakeasy & QR Code).
*   **Secure Password Storage**: Passwords are hashed using SHA-256 before storage.

### 2. Session Security
*   **Single Concurrent Session**: Users can only be logged in on one device at a time. Logging in from a new device automatically terminates the previous session.
*   **Hijack Detection**: Monitors `User-Agent` strings. If a session cookie is used from a different browser, it is immediately flagged as a hijack attempt and terminated.

### 3. Secure File Storage
*   **Cloud Persistence**: All data is stored in **MongoDB Atlas** (Cloud Database).
*   **AES-256-CBC Encryption**: Files are encrypted using AES-256-CBC with a secure key and IV before storage.
*   **RSA Digital Signatures**: Each file upload is digitally signed using the user's RSA private key to ensure authenticity and non-repudiation.
*   **Integrity Checks**: SHA-256 hashes and RSA signatures are verified upon download to ensure file integrity.

### 4. Role-Based Access Control (RBAC)
*   **Admin**: Can access all files.
*   **Faculty**: Can access their own files + Student files.
*   **Student**: Can only access their own files.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
*   Node.js installed.
*   A MongoDB Atlas Connection String.
*   A Gmail account (and App Password) for sending OTPs.

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment
Create a `.env` file in the root directory:
```properties
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-gmail-app-password
MONGO_URI=mongodb+srv://<user>:<password>@cluster0...
```

### 4. Run the Server
```bash
node server.js
```
*   Server runs at: `http://localhost:3000`
*   Database Viewer: `http://localhost:3000/db-viewer`

---

## 📖 Usage Guide (The Process)

### Step 1: Registration
1.  Go to `http://localhost:3000`.
2.  Click **"Register"**.
3.  Enter your details and real **Email Address**.
4.  Click **"Send OTP"**. Check your email inbox for the code.
5.  Enter the OTP and click **"Register"**.
6.  **Important**: Scan the **QR Code** with Google Authenticator to save your 2FA token.

### Step 2: Login
1.  Enter Username and Password.
2.  Enter the **6-digit 2FA code** from your Authenticator App.
3.  Upon success, you will see the Dashboard.

### Step 3: Secure File Upload
1.  Select a file and click **"Upload"**.
2.  The server encrypts the file using the **System Key** (`0xAA`).
3.  The encrypted blob is saved to MongoDB.

### Step 4: Download & Decrypt
1.  Click **"Safe Decrypt & Download"** on any file.
2.  The server fetches the encrypted data, decrypts it using the private key, verifies the hash, and sends the original file back.

### Step 5: Verify Security
*   **Database Viewer**: Visit `/db-viewer` to see the raw data (Hashed Passwords, Encrypted Hex Data).
*   **Concurrent Login**: Login on Chrome. Then login on Edge/Mobile. The Chrome session will be kicked out.

---

## 🏗️ Technology Stack
*   **Backend**: Node.js, Express.js
*   **Database**: MongoDB Atlas (Mongoose)
*   **Security**: AES-256 Encryption, RSA Digital Signatures, SHA-256 Hashing, Speakeasy (2FA)
*   **Frontend**: HTML5, CSS3, Vanilla JS
