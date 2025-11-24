# 🔐 4Auth  
### Quad-Factor Authentication System for Python Applications  
*A Combined Computer Security & Computer Networks Final Project*

4Auth is a hardened authentication framework written in Python that enforces **four identity factors** before granting access:

1. Password (bcrypt-hashed)  
2. TOTP (authenticator app)  
3. Face recognition (DeepFace + OpenCV)  
4. Device & context checks (MAC binding + time skew)

It uses a **TLS-secured client–server architecture**, an encrypted SQLite database, and a JSON-based protocol over sockets.

Core files:

- `server.py` — TLS server, database, crypto, verification pipeline  
- `client.py` — TLS client, webcam capture, login/register/recovery flows  

---

## 🎯 Project Goals

4Auth integrates objectives from:

### **Computer Security**
- Multi-factor authentication  
- Password hashing (bcrypt)  
- Biometric verification (DeepFace)  
- Symmetric encryption (Fernet/AES)  
- Time-based One-Time Passwords (TOTP)  
- Device identity checking (MAC binding)  
- Enforcement of password policy  
- Tamper-resistant time validation  
- Full logging and auditability  

### **Computer Networks**
- TCP socket communication  
- TLS encryption layer  
- Application protocol design  
- JSON serialization  
- Length-prefixed network framing  
- Multi-threaded client handling  
- Certificate-driven communication  

---

## 🧩 Four Identity Factors Required

### 1. 🗝️ Password — *Something You Know*

- Hashed with **bcrypt** using per-user salt.
- Enforced password policy:
  - Min 8 characters  
  - Must contain uppercase, digit, or special char  
- Verified server-side in constant time.

### 2. 📱 TOTP (Time-based One-Time Password) — *Something You Have*

- Server generates a new Base32 TOTP secret on registration.
- Stored encrypted via **Fernet**.
- A provisioning URI + QR code is returned to the client.
- User scans QR with Google/Microsoft Authenticator.
- Login uses a 6-digit TOTP verified via `pyotp`.

### 3. 🧑‍💻 Facial Recognition — *Something You Are*

- Client captures a webcam frame via OpenCV.
- Encodes JPEG → base64 → sends over TLS.
- Server decrypts stored face image.
- DeepFace performs a verification match.
- Requires real-face presence at login and recovery.

### 4. 💻 Device + Time Verification  
*Somewhere You Are + When You Are*

#### **MAC Binding**
- Account locked to device’s physical MAC.
- Prevents replay or reuse on unregistered devices.

#### **Time Skew Enforcement**
- Client sends UTC timestamp.
- Server fetches NTP time via `pool.ntp.org`.
- Rejects login if skew > 120 seconds.
- Prevents replay attacks and clock manipulation.

---

## 🔒 Data Security Architecture

### **Encrypted Secrets**
The server stores:

- Encrypted TOTP secret  
- Encrypted facial template (PNG bytes)  
- Bcrypt password hash  
- Bound MAC address  

### **SQLite Schema**

#### `users` table
| Field | Description |
|-------|-------------|
| `username` | primary key |
| `password_hash` | bcrypt hash |
| `face_image_enc` | encrypted PNG |
| `totp_secret_enc` | encrypted Base32 |
| `mac_address` | bound device identity |

#### `access_logs` table  
| Field | Description |
|--------|-------------|
| `id` | autoincrement PK |
| `ts_utc` | server UTC timestamp |
| `username` | nullable user |
| `action` | login/register/recovery |
| `success` | 1/0 |
| `detail` | message/details |

Every login, register, recovery attempt is logged.

---

# 📡 Network Protocol

### **Transport**
- Raw TCP socket  
- Wrapped fully in TLS 1.2+  
- Certificate & private key: `cert.pem`, `key.pem`  

### **Message framing**
Each message uses:

[4-byte big-endian length][JSON payload]

This avoids partial reads and guarantees framing even inside TLS.

### **Command codes**

| Code | Meaning |
|------|---------|
| `"100"` | Login |
| `"200"` | Register (admin-only) |
| `"300"` | Recover TOTP |
| `"310"` | Recover password |
| `"320"` | Recover face |
| `"330"` | Update MAC address |

Client sends → server responds with JSON containing:

- `status`: `"ok"` or `"error"`  
- `message`: human-readable text  
- Optional fields like `qr_png_b64` or `provisioning_uri`  

---

## 👤 Client Application (CLI)

### **Main Menu**
Log in

Register Account (admin only)

Recovery Options

Exit

### **Login Flow**
1. Username  
2. Password  
3. 6-digit TOTP  
4. Face capture  
5. MAC + timestamp auto-attached  
6. Server returns success/failure  
7. `login()` returns True/False  

### **Registration Flow**
- Admin secret required  
- Username, password  
- Face capture + MAC  
- Server returns TOTP QR + provisioning URI  

### **Recovery Menu**
Recover TOTP

Recover Password

Recover Face

Recover MAC

Each path requires a different combination of MFA components.

---

## 🖥️ Server Application

### At startup:
- Loads/creates `fernet.key`
- Creates/open SQLite DB
- Ensures tables exist
- Creates TLS context
- Listens on port 65432
- Spawns threads per client

### Server responsibilities:
- Enforce authentication logic  
- Verify each MFA factor  
- Handle secure storage of secrets  
- Perform biometric matching  
- Log every action  
- Return structured JSON  

---

# ▶️ How to Run

### **Start the server**
python server.py

markdown
Copy code

### **Start the client**
python client.py

---

# 📝 Summary

4Auth is a complete, production-style authentication system demonstrating:

- Bcrypt password hashing  
- DeepFace biometric authentication  
- TOTP provisioning and verification  
- Fernet-encrypted face and TOTP storage  
- MAC address device binding  
- Time-skew access protection  
- End-to-end TLS communication  
- Full logging of all security events  
- Custom JSON protocol over sockets  
- Secure client–server architecture  

This project satisfies the learning objectives of **Computer Security** and **Computer Networks**, merging them into one cohesive final deliverable.

---

# 📦 requirements.txt

opencv-python
numpy
Pillow
deepface
pyotp
qrcode
bcrypt
cryptography
ntplib
