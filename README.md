# 🔐 4Auth — Quad-Factor Authentication System  
*A Identity & Access Control Framework for Python Applications*

4Auth is a hardened multi-factor authentication system built with Python.  
It combines **cryptography**, **biometrics**, **network security**, and a **TLS-enabled client–server architecture** into a single high‑security authentication workflow.

This README explains the system in detail based directly on the actual source code I've made in:

- `better_admin.py` — TLS server, database, verification pipeline  
- `better_client.py` — TLS client, webcam capture, login/register flows  

---

# 🚀 Project Purpose

4Auth was designed as a combined **Computer Security** and **Computer Networks** final project.  

It demonstrates:

- Secure handling of authentication factors  
- Encrypted storage of sensitive data  
- Client–Server TCP communication using SSL  
- JSON-formatted protocol messages  
- Biometric verification using DeepFace  
- TOTP-based device-linked authentication  
- MAC address and time verification  
- Full audit logging  

---

# 🧩 Quad-Factor Authentication Breakdown

4Auth requires **all four** identity checks to succeed in order to authenticate a user.

---

## 1. 🗝️ Password — *Something You Know*

### How it's implemented
- Passwords are hashed using **bcrypt** with per-user random salt.
- Password policy enforced in `validate_password_policy()`:
  - Minimum 8 characters  
  - Must contain uppercase or digit or special character  

### Storage
- Stored in SQLite under `password_hash` (binary hash).

### Security Benefits
- Resistant to rainbow tables  
- Salts block precomputation attacks  
- bcrypt’s adaptive cost increases brute‑force difficulty  

---

## 2. 📱 TOTP (Time-based One-Time Password) — *Something You Have*

### How it's implemented
- During registration, a new Base32 TOTP secret is generated:
  ```python
  totp_secret = pyotp.random_base32()
  ```
- Secret is encrypted using **Fernet** and stored in `totp_secret_enc`.  
- A QR code is generated server-side using the provisioning URI:
  ```
  otpauth://totp/4Auth-Authentication:<username>?secret=<secret>
  ```
- Client scans QR using Microsoft/Google Authenticator.

### Login
- User enters 6‑digit TOTP  
- Server decrypts stored secret and verifies via:
  ```python
  totp.verify(token)
  ```

### Security Benefit
Even if a password leaks, attacker still needs the user’s physical device.

---

## 3. 🧑‍💻 Facial Recognition — *Something You Are*

### How it's implemented
- Client captures a JPEG webcam frame using OpenCV:
  ```python
  cv2.VideoCapture()
  ```
- Image is base64‑encoded and sent to server.

- Server decrypts stored face image, loads both images, and verifies identity using:
  ```python
  DeepFace.verify(probe_img, stored_img)
  ```

### Storage
- The facial template is stored as **encrypted PNG bytes** under `face_image_enc`.

### Security Benefit
- Strong biometric assurance  
- Cannot be bypassed by knowing passwords or stealing TOTP

---

## 4. 💻 MAC Address + Time Verification — *Device & Context*

### MAC Binding
- Client collects MAC using:
  ```python
  uuid.getnode()
  ```
- Server compares against stored MAC to ensure login is from the registered device.

### Time Skew Verification
- Client sends current UTC timestamp  
- Server checks time difference:
  ```python
  skew <= 120 seconds
  ```

### Security Benefit
- Prevents replay attacks  
- Prevents automated authentication from unauthorized machines  
- Ensures system clock tampering is ineffective  

---

# 🔒 Data Security & Cryptography

## SQLite Tables

### `users` table
| Field | Description |
|-------|-------------|
| username | Primary key |
| password_hash | bcrypt hash |
| face_image_enc | Fernet-encrypted PNG bytes |
| totp_secret_enc | Fernet-encrypted TOTP secret |
| mac_address | Device binding |

### `access_logs` table
Records every event:
- Timestamp  
- Username  
- Action (login/register)  
- Success/fail  
- Details  

---

# 📦 Encryption & Key Handling

4Auth uses **Fernet symmetric encryption** for:
- Face images  
- TOTP secrets  

The key file:
```
fernet.key
```
is automatically created if missing.

### Why Fernet?
- AES‑128 in CBC mode  
- HMAC-SHA256 for integrity  
- Simple and safe key management  

---

# 📡 Network Protocol (Client ↔ Server)

4Auth uses:
- Raw TCP socket  
- Wrapped in **SSL/TLS**  
- With server certificate `cert.pem` and key `key.pem`

### Message Format
Each message is:

```
[4‑byte big-endian length][JSON payload]
```

Example server command handler:

- `"200"` → Register user  
- `"100"` → Login attempt  

Responses are structured JSON objects.

---

# 🖥️ Client Program (CLI)

The client provides a menu:

```
1. Log in
2. Register Account
3. Exit
```

### Registration Flow
1. Prompt username & password  
2. Capture face image  
3. Send MAC  
4. Server returns QR code for TOTP setup  
5. QR shown automatically using PIL  

### Login Flow
1. Username & password  
2. User enters TOTP code  
3. Capture face image  
4. MAC + timestamp auto-attached  
5. Server returns authentication result  

---

# 🏗️ Server Program (Admin Side)

The server:

- Initializes DB & tables  
- Loads/creates Fernet key  
- Listens on `127.0.0.1:65432`  
- Wraps incoming connection in TLS  
- Expects JSON commands in a loop  
- Logs every action  
- Returns structured JSON responses  

---

# ▶️ Running the System

## Start the Server
```
python better_admin.py
```

## Start the Client
```
python better_client.py
```

---

# 📝 Summary

4Auth is a fully functional, secure authentication pipeline implementing:

- **bcrypt hashing**  
- **DeepFace biometrics**  
- **TOTP with QR provisioning**  
- **Device MAC binding**  
- **Time-based access control**  
- **End-to-end TLS encrypted communication**  
- **Encrypted database secrets**  
- **Complete logging and auditing**  

It showcases principles from both **Computer Security** and **Computer Networks** in one useful system.
