import socket
import sqlite3
import ssl
import json
import base64
import struct
import io
import uuid
import re
from datetime import datetime, timezone
import threading

import cv2
import numpy as np
from PIL import Image
from deepface import DeepFace
import pyotp
import qrcode
import bcrypt
from cryptography.fernet import Fernet
import ntplib  # for NTP time

HOST = "127.0.0.1"
PORT = 65432

# =============================
# Admin control (only admin can create users)
# =============================
# For a real deployment, WE SHOULD load from env var or config file!!!!1
ADMIN_SHARED_SECRET = "CHANGE_THIS_ADMIN_SECRET"


# =============================
# Key management for encrypting at-rest secrets (TOTP, face image)
# =============================
FERNET_KEY_PATH = "fernet.key"


def _load_or_create_fernet_key(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)
        return key


ENCRYPTION_KEY = _load_or_create_fernet_key(FERNET_KEY_PATH)
cipher = Fernet(ENCRYPTION_KEY)

# =============================
# Database Setup
# =============================
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL,
    face_image_enc BLOB NOT NULL,
    totp_secret_enc BLOB NOT NULL,
    mac_address TEXT NOT NULL
)
"""
)

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail TEXT
)
"""
)
conn.commit()

# =============================
# Utilities
# =============================


def _b64_to_image(img_b64: str) -> np.ndarray | None:
    try:
        data = base64.b64decode(img_b64)
        if not data:
            return None
        arr = np.frombuffer(data, np.uint8)
        if arr.size == 0:
            return None
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img
    except Exception:
        return None



def _image_bytes(img: np.ndarray, fmt: str = "PNG") -> bytes:
    pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    buf = io.BytesIO()
    pil_img.save(buf, format=fmt)
    return buf.getvalue()


def _json_send(sock, obj: dict):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)))
    sock.sendall(payload)


def _json_recv(sock) -> dict:
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("Connection closed (no header)")
    length = struct.unpack(">I", header)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed during body")
        data += chunk
    return json.loads(data.decode("utf-8"))


def _log(username: str | None, action: str, success: bool, detail: str = ""):
    cursor.execute(
        "INSERT INTO access_logs (ts_utc, username, action, success, detail) VALUES (?, ?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            username,
            action,
            1 if success else 0,
            detail[:500],
        ),
    )
    conn.commit()


# =============================
# Security helpers
# =============================


def validate_password_policy(pw: str) -> bool:
    if len(pw) < 8:
        return False
    # Must contain at least one uppercase letter OR digit OR special char
    return bool(re.search(r"[A-Z0-9!@#$%^&*]", pw))


def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())


def check_password(pw: str, pw_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)
    except Exception:
        return False


def encrypt_secret(raw: bytes) -> bytes:
    return cipher.encrypt(raw)


def decrypt_secret(enc: bytes) -> bytes:
    return cipher.decrypt(enc)


def get_ntp_utc_time() -> datetime:
    """
    Get current UTC time via NTP.
    Falls back to local UTC if NTP fails.
    """
    try:
        client = ntplib.NTPClient()
        response = client.request("pool.ntp.org", version=3)
        return datetime.fromtimestamp(response.tx_time, tz=timezone.utc)
    except Exception:
        # Fallback – still UTC but not NTP-synced
        return datetime.now(timezone.utc)


# =============================
# Core user functions
# =============================


def create_user(username: str, password: str, face_b64: str, totp_mode: str, mac: str):
    if not validate_password_policy(password):
        return {
            "status": "error",
            "message": "Weak password (min 8 chars and include uppercase/digit/special).",
        }

    pw_hash = hash_password(password)

    face_img = _b64_to_image(face_b64)
    if face_img is None:
        return {"status": "error", "message": "Invalid face image."}
    face_bytes = _image_bytes(face_img, "PNG")
    face_enc = encrypt_secret(face_bytes)

    if totp_mode == "new":
        totp_secret = pyotp.random_base32().encode("utf-8")
    else:
        # could accept existing secret; for now always new
        totp_secret = pyotp.random_base32().encode("utf-8")

    totp_enc = encrypt_secret(totp_secret)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, face_image_enc, totp_secret_enc, mac_address) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, face_enc, totp_enc, mac),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Username already exists."}

    # Build provisioning URI and QR
    uri = pyotp.totp.TOTP(totp_secret.decode("utf-8")).provisioning_uri(
        name=username, issuer_name="4Auth-Authentication"
    )
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    _log(username, "register", True, "User created")
    return {"status": "ok", "qr_png_b64": qr_b64, "provisioning_uri": uri}


def get_user_row(username: str):
    cursor.execute(
        "SELECT username, password_hash, face_image_enc, totp_secret_enc, mac_address FROM users WHERE username=?",
        (username,),
    )
    return cursor.fetchone()


def verify_face(username: str, probe_b64: str) -> bool:
    cursor.execute("SELECT face_image_enc FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        return False
    stored_png = decrypt_secret(row[0])
    stored_img = cv2.imdecode(np.frombuffer(stored_png, np.uint8), cv2.IMREAD_COLOR)
    probe_img = _b64_to_image(probe_b64)
    try:
        result = DeepFace.verify(probe_img, stored_img, enforce_detection=True)
        return bool(result.get("verified", False))
    except Exception:
        return False


def get_totp(username: str) -> pyotp.TOTP | None:
    cursor.execute("SELECT totp_secret_enc FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        return None
    secret = decrypt_secret(row[0]).decode("utf-8")
    return pyotp.TOTP(secret)


def verify_totp(username: str, token: str) -> bool:
    totp = get_totp(username)
    if not totp:
        return False
    return bool(totp.verify(token))


def verify_mac(username: str, client_mac: str) -> bool:
    cursor.execute("SELECT mac_address FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    return bool(row and row[0].lower() == client_mac.lower())


def verify_time(client_ts_iso: str, max_skew_seconds: int = 120) -> bool:
    try:
        client_ts = datetime.fromisoformat(client_ts_iso)
        if client_ts.tzinfo is None:
            client_ts = client_ts.replace(tzinfo=timezone.utc)
        server_ts = get_ntp_utc_time()
        skew = abs((server_ts - client_ts).total_seconds())
        return skew <= max_skew_seconds
    except Exception:
        return False


def do_login(
    username: str,
    password: str,
    token: str,
    face_b64: str,
    mac: str,
    client_ts_iso: str,
) -> dict:
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        _log(username, "login", False, "No such user")
        return {"status": "error", "message": "Invalid username or password."}

    if not check_password(password, row[0]):
        _log(username, "login", False, "Bad password")
        return {"status": "error", "message": "Invalid username or password."}

    if not verify_face(username, face_b64):
        _log(username, "login", False, "Face failed")
        return {"status": "error", "message": "Face verification failed."}

    if not verify_totp(username, token):
        _log(username, "login", False, "TOTP failed")
        return {"status": "error", "message": "TOTP verification failed."}

    if not verify_mac(username, mac):
        _log(username, "login", False, "MAC mismatch")
        return {"status": "error", "message": "Unauthorized device."}

    if not verify_time(client_ts_iso):
        _log(username, "login", False, "Time skew")
        return {"status": "error", "message": "Time out of allowed window."}

    _log(username, "login", True, "Success")
    return {"status": "ok", "message": "Login successful."}


# =============================
# Recovery operations
# =============================

def recover_totp(
    username: str,
    password: str,
    face_b64: str,
    mac: str,
    client_ts_iso: str,
) -> dict:
    """
    Recover TOTP if you can provide: password + face + MAC + valid time.
    """
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        _log(username, "recover_totp", False, "No such user")
        return {"status": "error", "message": "User not found."}

    if not check_password(password, row[0]):
        _log(username, "recover_totp", False, "Bad password")
        return {"status": "error", "message": "Invalid credentials."}

    if not verify_face(username, face_b64):
        _log(username, "recover_totp", False, "Face failed")
        return {"status": "error", "message": "Face verification failed."}

    if not verify_mac(username, mac):
        _log(username, "recover_totp", False, "MAC mismatch")
        return {"status": "error", "message": "Unauthorized device."}

    if not verify_time(client_ts_iso):
        _log(username, "recover_totp", False, "Time skew")
        return {"status": "error", "message": "Time out of allowed window."}

    # All other factors ok → issue new TOTP
    new_secret = pyotp.random_base32().encode("utf-8")
    new_enc = encrypt_secret(new_secret)
    cursor.execute(
        "UPDATE users SET totp_secret_enc=? WHERE username=?",
        (new_enc, username),
    )
    conn.commit()

    uri = pyotp.totp.TOTP(new_secret.decode("utf-8")).provisioning_uri(
        name=username, issuer_name="4Auth-Authentication"
    )
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    _log(username, "recover_totp", True, "TOTP reset")
    return {
        "status": "ok",
        "message": "TOTP secret reset. Scan the new QR code.",
        "qr_png_b64": qr_b64,
        "provisioning_uri": uri,
    }


def recover_password(
    username: str,
    new_password: str,
    token: str,
    face_b64: str,
    mac: str,
    client_ts_iso: str,
) -> dict:
    """
    Recover password if you can provide: TOTP + face + MAC + valid time.
    """
    if not validate_password_policy(new_password):
        return {
            "status": "error",
            "message": "Weak password (min 8 chars and include uppercase/digit/special).",
        }

    if not verify_face(username, face_b64):
        _log(username, "recover_password", False, "Face failed")
        return {"status": "error", "message": "Face verification failed."}

    if not verify_totp(username, token):
        _log(username, "recover_password", False, "TOTP failed")
        return {"status": "error", "message": "TOTP verification failed."}

    if not verify_mac(username, mac):
        _log(username, "recover_password", False, "MAC mismatch")
        return {"status": "error", "message": "Unauthorized device."}

    if not verify_time(client_ts_iso):
        _log(username, "recover_password", False, "Time skew")
        return {"status": "error", "message": "Time out of allowed window."}

    pw_hash = hash_password(new_password)
    cursor.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (pw_hash, username),
    )
    conn.commit()
    _log(username, "recover_password", True, "Password reset")
    return {"status": "ok", "message": "Password reset successful."}


def recover_face(
    username: str,
    password: str,
    token: str,
    new_face_b64: str,
    mac: str,
    client_ts_iso: str,
) -> dict:
    """
    Re-enroll face if you can provide: password + TOTP + MAC + valid time.
    """
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        _log(username, "recover_face", False, "No such user")
        return {"status": "error", "message": "User not found."}

    if not check_password(password, row[0]):
        _log(username, "recover_face", False, "Bad password")
        return {"status": "error", "message": "Invalid credentials."}

    if not verify_totp(username, token):
        _log(username, "recover_face", False, "TOTP failed")
        return {"status": "error", "message": "TOTP verification failed."}

    if not verify_mac(username, mac):
        _log(username, "recover_face", False, "MAC mismatch")
        return {"status": "error", "message": "Unauthorized device."}

    if not verify_time(client_ts_iso):
        _log(username, "recover_face", False, "Time skew")
        return {"status": "error", "message": "Time out of allowed window."}

    face_img = _b64_to_image(new_face_b64)
    if face_img is None:
        return {"status": "error", "message": "Invalid new face image."}
    face_bytes = _image_bytes(face_img, "PNG")
    face_enc = encrypt_secret(face_bytes)

    cursor.execute(
        "UPDATE users SET face_image_enc=? WHERE username=?",
        (face_enc, username),
    )
    conn.commit()
    _log(username, "recover_face", True, "Face re-enrolled")
    return {"status": "ok", "message": "Face re-enrolled successfully."}


def recover_mac(
    username: str,
    password: str,
    token: str,
    face_b64: str,
    new_mac: str,
    client_ts_iso: str,
) -> dict:
    """
    Update MAC if you can provide: password + TOTP + face + valid time.
    """
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    if not row:
        _log(username, "recover_mac", False, "No such user")
        return {"status": "error", "message": "User not found."}

    if not check_password(password, row[0]):
        _log(username, "recover_mac", False, "Bad password")
        return {"status": "error", "message": "Invalid credentials."}

    if not verify_totp(username, token):
        _log(username, "recover_mac", False, "TOTP failed")
        return {"status": "error", "message": "TOTP verification failed."}

    if not verify_face(username, face_b64):
        _log(username, "recover_mac", False, "Face failed")
        return {"status": "error", "message": "Face verification failed."}

    if not verify_time(client_ts_iso):
        _log(username, "recover_mac", False, "Time skew")
        return {"status": "error", "message": "Time out of allowed window."}

    cursor.execute(
        "UPDATE users SET mac_address=? WHERE username=?",
        (new_mac,username),
    )
    conn.commit()
    _log(username, "recover_mac", True, "MAC updated")
    return {"status": "ok", "message": "MAC address updated successfully."}


# =============================
# Per-connection handler
# =============================


def handle_client(raw_conn, addr, context):
    with raw_conn:
        print(f"TCP connected by {addr}")
        try:
            with context.wrap_socket(raw_conn, server_side=True) as ssock:
                print(f"TLS handshake done with {addr}")

                while True:
                    try:
                        req = _json_recv(ssock)
                    except Exception:
                        break

                    cmd = req.get("cmd")

                    if cmd == "200":  # Register (admin-only)
                        admin_secret = req.get("admin_secret", "")
                        if admin_secret != ADMIN_SHARED_SECRET:
                            out = {
                                "status": "error",
                                "message": "Admin authorization failed.",
                            }
                            _json_send(ssock, out)
                            continue

                        out = create_user(
                            username=req.get("username", ""),
                            password=req.get("password", ""),
                            face_b64=req.get("faceID", ""),
                            totp_mode=req.get("totp", "new"),
                            mac=req.get("mac", ""),
                        )
                        _json_send(ssock, out)

                    elif cmd == "100":  # Login
                        out = do_login(
                            username=req.get("username", ""),
                            password=req.get("password", ""),
                            token=req.get("totp", ""),
                            face_b64=req.get("faceID", ""),
                            mac=req.get("mac", ""),
                            client_ts_iso=req.get("client_ts_utc", ""),
                        )
                        _json_send(ssock, out)

                    elif cmd == "300":  # Recover TOTP
                        out = recover_totp(
                            username=req.get("username", ""),
                            password=req.get("password", ""),
                            face_b64=req.get("faceID", ""),
                            mac=req.get("mac", ""),
                            client_ts_iso=req.get("client_ts_utc", ""),
                        )
                        _json_send(ssock, out)

                    elif cmd == "310":  # Recover password
                        out = recover_password(
                            username=req.get("username", ""),
                            new_password=req.get("new_password", ""),
                            token=req.get("totp", ""),
                            face_b64=req.get("faceID", ""),
                            mac=req.get("mac", ""),
                            client_ts_iso=req.get("client_ts_utc", ""),
                        )
                        _json_send(ssock, out)

                    elif cmd == "320":  # Re-enroll face
                        out = recover_face(
                            username=req.get("username", ""),
                            password=req.get("password", ""),
                            token=req.get("totp", ""),
                            new_face_b64=req.get("new_faceID", ""),
                            mac=req.get("mac", ""),
                            client_ts_iso=req.get("client_ts_utc", ""),
                        )
                        _json_send(ssock, out)

                    elif cmd == "330":  # Update MAC
                        out = recover_mac(
                            username=req.get("username", ""),
                            password=req.get("password", ""),
                            token=req.get("totp", ""),
                            face_b64=req.get("faceID", ""),
                            new_mac=req.get("new_mac", ""),
                            client_ts_iso=req.get("client_ts_utc", ""),
                        )
                        _json_send(ssock, out)

                    else:
                        _json_send(
                            ssock,
                            {"status": "error", "message": "Unknown command."},
                        )
        finally:
            print(f"Connection with {addr} closed")


# =============================
# TLS Server main loop
# =============================

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on {HOST}:{PORT}")

        while True:
            raw_conn, addr = s.accept()
            # Handle each client in a new thread!!!! This can get heavy with many clients!!!
            t = threading.Thread(
                target=handle_client, args=(raw_conn, addr, context), daemon=True
            )
            t.start()


if __name__ == "__main__":
    main()
