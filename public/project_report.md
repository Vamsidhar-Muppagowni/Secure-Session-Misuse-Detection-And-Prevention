# Secure Session & File Vault (Demonstration Implementation)

## 1. Project Overview
This project is a **Concept Demonstration** of a secure file vault. It simulates real-world security mechanisms using simplified, transparent logic to make the concepts easier to understand and present.

### Core Security Concepts Demonstrated:
1.  **Session Security**: Preventing Session Hijacking by binding sessions to User-Agents.
2.  **Confidentiality**: Encrypting files so they cannot be read directly from the disk.
3.  **Integrity**: Hashing files to ensure they haven't been modified.
4.  **Authorization (RBAC)**: Ensuring students can't see faculty files.

---

## 2. Implementation Logic (How it Works)

This implementation avoids "black-box" libraries in favor of manual logic you can explain line-by-line.

### A. Authentication & Session Management
Instead of hiding session logic inside a library, we handle it manually:
*   **The Session Store**: A simple global object (`sessions = {}`) on the server holds all active users.
*   **The Token**: When you login, we generate a random `sessionId`.
*   **The Cookie**: We manually send a `Set-Cookie` header. The browser sends this back on every request.
*   **Misuse Detection**:
    *   When a session is created, we save the user's **Browser Signature** (User-Agent).
    *   On *every* request, we compare the incoming User-Agent with the saved one.
    *   **Demo**: If an attacker steals the Session ID cookie but uses a different browser, the server rejects it!

### B. "Transparent" Encryption (XOR Cipher)
To demonstrate encryption without complex math, we use a **Symmetrical XOR Cipher**.
*   **Logic**: Every byte of the file is combined with a key (e.g., `0xAA`).
    *   `EncryptedByte = OriginalByte XOR Key`
    *   `DecryptedByte = EncryptedByte XOR Key` (It minimizes back!)
*   **Why?** This scrambles the file effectively for the lab, proving the concept of "Data at Rest Encryption". If you open `files.json`, the data looks like garbage text (hex).

### C. Password Hashing
*   We use standard **SHA-256** hashing.
*   The server receives the password, hashes it, and compares it to the stored hash. Plaintext passwords are never stored.

---

## 3. How to Demonstrate This
1.  **Register a User**: Create a `student` account.
2.  **Login**: Shows successful session creation.
3.  **Upload a File**:
    *   Upload a text file.
    *   Show `data/files.json`: You will see the "data" field is a long Hex string, not the original text. This proves **Encryption**.
4.  **Download**: The server decrypts it on the fly, giving you back the original file.
5.  **Access Control**: Login as a different student. You won't see the first student's files.

---

## 4. Algorithms Used

Since this is a security demonstration, we use transparent algorithms to show *how* they work, rather than hiding behind complex libraries.

### 1. Password Hashing: SHA-256
*   **Algorithm**: Secure Hash Algorithm 256-bit (`SHA-256`).
*   **Purpose**: To ensure passwords are not stored in plaintext.
*   **Implementation**:
    *   Input: `password123`
    *   Operation: `crypto.createHash('sha256').update(input).digest('hex')`
    *   Output: `ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f`
    *   **Security Property**: One-way function (cannot be reversed).

### 2. File Encryption: Symmetrical XOR Cipher
*   **Algorithm**: Custom Vernam-style XOR Cipher.
*   **Purpose**: To demonstrate "Data at Rest" encryption. Even if a hacker steals the hard drive (`files.json`), they cannot read the file contents.
*   **Logic**:
    *   `Key`: `0xAA` (10101010 in binary).
    *   `Encrypt`: `CipherByte = PlainByte XOR Key`.
    *   `Decrypt`: `PlainByte = CipherByte XOR Key`.
    *   **Why XOR?** It is the foundation of modern stream ciphers (like RC4 or AES-CTR) but is simple enough to understand in one line of code.

### 3. Session Management: User-Agent Binding
*   **Algorithm**: Context-Aware Session Validation.
*   **Purpose**: To prevent Session Hijacking (Replay Attacks).
*   **Logic**:
    1.  On Login, server records: `SessionID -> { User: "Student", Browser: "Chrome v120" }`.
    2.  On Request, server checks: Does the incoming request come from "Chrome v120"?
    3.  If **YES** -> Allow.
    4.  If **NO** (e.g., "Safari") -> **Destroy Session immediately**.

---

## 5. Algorithm Pseudocode

Here is the explicit logic for the core security functions.

### A. XOR Encryption (Symmetrical)
**Input**: `Buffer` (File Data), `Key` (0xAA)
**Output**: `Buffer` (Encrypted Data)

```python
FUNCTION XOR_Encrypt(data, key):
    # Create empty result buffer of same size
    result = NEW_BUFFER(data.length)
    
    # Loop through every byte
    FOR i FROM 0 TO data.length - 1:
        originalByte = data[i]
        
        # XOR Operation (^)
        # If bits are different -> 1, same -> 0
        encryptedByte = originalByte XOR key
        
        result[i] = encryptedByte
    END FOR
    
    RETURN result
END FUNCTION
```
*Note: To Decrypt, run the exact same function again.*

### B. Password Hashing (SHA-256)
**Input**: `password` (String)
**Output**: `hash` (Hex String)

```python
FUNCTION Hash_Password(password):
    # Initialize SHA-256 Hasher
    hasher = CREATE_HASH('sha256')
    
    # Feed password into hasher
    hasher.UPDATE(password)
    
    # Finalize and get Hexadecimal string
    digest = hasher.DIGEST('hex')
    
    RETURN digest
END FUNCTION
```

### C. Session Validation (Security Check)
**Input**: `IncomingRequest` (Cookie, User-Agent)
**Output**: `Allow` OR `Deny`

```python
FUNCTION Validate_Session(request):
    # 1. Extract Session ID from Cookie Header
    cookieString = request.headers['cookie']
    sessionId = PARSE_COOKIE(cookieString, 'sessionId')
    
    # 2. Check if Session exists in Server Memory
    IF sessionId IS NULL OR sessions[sessionId] IS NULL:
        RETURN “401 Unauthorized”
    
    # 3. Retrieve Session Data
    sessionData = sessions[sessionId]
    
    # 4. Misuse Detection: Compare Browser Signatures
    storedUserAgent = sessionData.userAgent
    currentUserAgent = request.headers['user-agent']
    
    IF storedUserAgent IS NOT EQUAL TO currentUserAgent:
        # SECURITY ALERT: Mismatch detected!
        DELETE sessions[sessionId]  # Destroy Session
        RETURN “403 Forbidden: Potential Hijack”
        
    # 5. Success
    RETURN “200 OK”
END FUNCTION
```

---

## 6. Additional Security Simulations

The dashboard includes two specific tools to demonstrate other cryptographic concepts.

### A. Diffie-Hellman Key Exchange Simulator
*   **Concept**: How two parties (Alice & Bob) agree on a secret key over an insecure channel without meeting.
*   **In this Demo**: The button simulates the **initial handshake**.
    *   Server generates a large Prime Number (`p`) and a Generator (`g`).
    *   It simulates "Alice" sending her Public Key.
    *   **Educational Value**: Shows the parameters required for a secure handshake (Prime, Generator, Public Key).

### B. Encoding Tool (Base64)
*   **Concept**: **Encoding is NOT Encryption.**
*   **Purpose**: To show the difference between *hiding* data (Encryption) and *representing* data (Encoding).
*   **Demo**:
    *   Type "Hello". Click Encode -> `SGVsbG8=`.
    *   **Lesson**: Anyone can decode Base64. It provides **no security**, only data formatting.



