# 🔐 4Auth — Quad-Factor Authentication for High-Security Python Applications

## Abstract

Providing authorization to highly sensitive applications is essential to the protection of confidential or classified data. Companies fear statistics such as one from Cybers Guards stating that *“Every 39 seconds, a hacker attempts an attack somewhere on the internet.”* This means the work factor for attackers to break into systems or applications must be increasingly effective in a world where login portals are in front of nearly every major application on the web.

To protect digital resources, organizations employ a branch of cybersecurity called **Identity and Access Management (IAM)** — a framework for controlling access to sensitive systems and data. The IAM principle relies on requiring users to verify their identity through one or more **access control factors**, commonly categorized as:

- **Something you know** (e.g., password)
- **Something you have** (e.g., security token or OTP)
- **Something you are** (e.g., biometrics)
- **Somewhere you are** (e.g., geolocation)
- **Something you do** (e.g., behavioral patterns)

Each factor adds a layer of defense, but individually, they can still be compromised. To mitigate this risk, systems employ **multi-factor authentication (MFA)** — combining multiple factors so that breaching one alone is insufficient to gain access.

**4Auth** takes this concept further. It enforces **four distinct factors of authentication** for highly sensitive applications written in Python, creating a security model designed to withstand both brute-force and identity-based attacks.

---

## 🔧 Introduction

**4Auth** significantly increases the security of any login portal by combining multiple independent authentication mechanisms. By enforcing a high *work factor*, 4Auth makes it exceptionally difficult for attackers to compromise an account, even if one or more factors are partially exposed.

The four access control factors implemented are:

| Access Control Factor | Type of Control | Implementing Technology |
|------------------------|-----------------|--------------------------|
| **Something you know** | Password | SHA-256 Hashed Password Storage |
| **Something you have** | One-Time Password (OTP) | Microsoft Authenticator |
| **Something you are** | Face ID Recognition | DeepFace (Python Module) |
| **Some defined time** | Time-Based Access Control | Current Time = Defined Time Comparison |

Each factor has its own role, strengths, and limitations, but together they form a powerful composite security system.

---

## 🧠 System Design Overview

### 1. Something You Know — Password

**Overview:**  
Users authenticate using a username and password pair. Passwords are hashed using the **SHA-256** algorithm before being stored to prevent plaintext exposure.

**Technology Used:**  
- `hashlib` (Python Standard Library)

**Strengths:**  
- Simple and well-understood.  
- Resistant to plaintext theft when hashed correctly.

**Weaknesses:**  
- Vulnerable to credential leaks or brute-force attacks if password hygiene is poor.

---

### 2. Something You Have — One-Time Password (OTP)

**Overview:**  
After password validation, users must provide a **One-Time Password** generated from an authenticator app like Microsoft Authenticator.

**Technology Used:**  
- `pyotp` for TOTP (Time-based One-Time Passwords)

**Strengths:**  
- Dynamic, time-sensitive codes reduce exposure to replay attacks.  
- Adds an independent second factor tied to a physical device.

**Weaknesses:**  
- Device loss or time drift may temporarily block legitimate access.  

---

### 3. Something You Are — Face ID Recognition

**Overview:**  
A biometric layer using **DeepFace** ensures that the user physically matches their registered face.

**Technology Used:**  
- `deepface` (Open Source Python Facial Recognition Library)

**Strengths:**  
- Difficult to spoof without physical likeness.  
- Provides human identity assurance beyond credentials.

**Weaknesses:**  
- Sensitive to lighting and camera quality.  
- Privacy and data storage of facial templates require careful handling.

---

### 4. Some Defined Time — Time-Based Access Context

**Overview:**  
Adds a temporal access rule — authentication is only valid within a defined time range or synchronized time window.

**Technology Used:**  
- Python `datetime` module for precise time comparison.

**Strengths:**  
- Mitigates automated overnight or off-hour attacks.  
- Adds an environmental constraint to login attempts.

**Weaknesses:**  
- Legitimate users may face access limitations outside defined time frames.  

---

## 🧩 The Power of Four — Combined Authentication

When all four factors are combined, 4Auth constructs a **multi-layered verification chain** that is exponentially harder to breach than any single factor system. The probability of successful unauthorized access becomes negligible without physical, cognitive, and contextual compromise.

4Auth’s architecture demonstrates that true digital trust can be engineered — not merely assumed — through compounding layers of identity assurance.

---

## 🐞 Bugs & Known Issues

| Module | Issue | Status |
|---------|--------|--------|
| Password | None known |  |
| OTP | None known| |
| Face ID | None known| |
| Time-Based | None known |  |

---

## ⚙️ Installation & Setup

```bash
# Clone the repository
git clone https://github.com/<your-username>/4Auth.git
cd 4Auth

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # (Windows: venv\Scripts\activate)

# Install dependencies
pip install -r requirements.txt
