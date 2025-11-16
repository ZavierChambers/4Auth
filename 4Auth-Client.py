import socket
import ssl
import cv2
import json
import base64
import struct
import uuid
from datetime import datetime, timezone
from PIL import Image
import io

HOST = "127.0.0.1"
PORT = 65432

# ---------------------------
# Helpers
# ---------------------------


def capture_photo_bytes(device_index: int = 0, warmup_frames: int = 5, jpeg_quality: int = 90) -> bytes:
    cap = cv2.VideoCapture(device_index, cv2.CAP_DSHOW if hasattr(cv2, "CAP_DSHOW") else 0)
    try:
        if not cap.isOpened():
            raise RuntimeError("Cannot open camera")
        for _ in range(max(0, warmup_frames)):
            ret, _ = cap.read()
        ret, frame = cap.read()
        if not ret or frame is None:
            raise RuntimeError("Failed to capture image")
        success, encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), jpeg_quality])
        if not success:
            raise RuntimeError("Failed to encode image")
        return encoded.tobytes()
    finally:
        cap.release()


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

#THIS NEEDS TO RETURN A STANDARD MAC ADDRESS FORMAT
def get_mac() -> str:
    mac_int = uuid.getnode()
    # Converting to a standard MAC address format
    mac_str = ":".join(f"{(mac_int >> ele) & 0xFF:02x}" for ele in range(40, -1, -8))
    return mac_str


def show_png_b64(png_b64: str):
    if not png_b64:
        print("No QR image provided.")
        return
    raw = base64.b64decode(png_b64)
    img = Image.open(io.BytesIO(raw))
    img.show()

# Current UTC time in ISO 8601 format!!!
def current_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def capture_face_b64() -> str:
    print("Please prepare for a capture of your face...")
    img_bytes = capture_photo_bytes()
    return base64.b64encode(img_bytes).decode("ascii")


# ---------------------------
# Flows
# ---------------------------

def login(ssock):
    #Let's use a dictionary to hold user inputs!!
    user_input_dic = {}
    user_input_dic["cmd"] = "100"
    user_input_dic["username"] = input("Username: ").strip()
    user_input_dic["password"] = input("Password: ").strip()
    user_input_dic["totp"] = input("Authenticator 6-digit code: ").strip()
    user_input_dic["faceID"] = capture_face_b64()
    user_input_dic["mac"] = get_mac()
    user_input_dic["client_ts_utc"] = current_utc_iso()
    # Send the login request
    _json_send(ssock, user_input_dic)
    resp = _json_recv(ssock)
    print("Server:", resp.get("message", resp))


def register_account(ssock):
    admin_secret = input("Admin Secret (required to register new users): ").strip()

    user_input_dic = {}
    user_input_dic["cmd"] = "200"
    user_input_dic["admin_secret"] = admin_secret
    user_input_dic["username"] = input("New Username: ").strip()
    user_input_dic["password"] = input("New Password: ").strip()
    user_input_dic["totp"] = "new"
    user_input_dic["faceID"] = capture_face_b64()
    user_input_dic["mac"] = get_mac()

    _json_send(ssock, user_input_dic)
    resp = _json_recv(ssock)

    if resp.get("status") == "ok":
        print("Account Created. Scan the QR that opens.")
        show_png_b64(resp.get("qr_png_b64", ""))
        print("If the QR did not open, use this URI in your authenticator app:")
        print(resp.get("provisioning_uri", ""))
    else:
        print("Registration failed:", resp.get("message", resp))


# ------ Recovery flows ------

def recover_totp(ssock):
    print("\n--- Recover TOTP (need password + face + MAC + time) ---")
    data = {
        "cmd": "300",
        "username": input("Username: ").strip(),
        "password": input("Current Password: ").strip(),
        "faceID": capture_face_b64(),
        "mac": get_mac(),
        "client_ts_utc": current_utc_iso(),
    }
    _json_send(ssock, data)
    resp = _json_recv(ssock)
    print("Server:", resp.get("message", resp))
    if resp.get("status") == "ok":
        show_png_b64(resp.get("qr_png_b64", ""))
        print("New TOTP URI:", resp.get("provisioning_uri", ""))


def recover_password(ssock):
    print("\n--- Recover Password (need TOTP + face + MAC + time) ---")
    data = {
        "cmd": "310",
        "username": input("Username: ").strip(),
        "new_password": input("New Password: ").strip(),
        "totp": input("Current Authenticator 6-digit code: ").strip(),
        "faceID": capture_face_b64(),
        "mac": get_mac(),
        "client_ts_utc": current_utc_iso(),
    }
    _json_send(ssock, data)
    resp = _json_recv(ssock)
    print("Server:", resp.get("message", resp))


def recover_face(ssock):
    print("\n--- Re-enroll Face (need password + TOTP + MAC + time) ---")
    data = {
        "cmd": "320",
        "username": input("Username: ").strip(),
        "password": input("Current Password: ").strip(),
        "totp": input("Current Authenticator 6-digit code: ").strip(),
        "new_faceID": capture_face_b64(),
        "mac": get_mac(),
        "client_ts_utc": current_utc_iso(),
    }
    _json_send(ssock, data)
    resp = _json_recv(ssock)
    print("Server:", resp.get("message", resp))


def recover_mac(ssock):
    print("\n--- Update MAC (need password + TOTP + face + time) ---")
    data = {
        "cmd": "330",
        "username": input("Username: ").strip(),
        "password": input("Current Password: ").strip(),
        "totp": input("Current Authenticator 6-digit code: ").strip(),
        "faceID": capture_face_b64(),
        "new_mac": input("New MAC (or leave blank to use this device's MAC): ").strip() or get_mac(),
        "client_ts_utc": current_utc_iso(),
    }
    _json_send(ssock, data)
    resp = _json_recv(ssock)
    print("Server:", resp.get("message", resp))


def recovery_menu(ssock):
    while True:
        choice = input(
            "\nRecovery Menu:\n"
            "1. Recover TOTP (lost phone)\n"
            "2. Recover Password (forgot password)\n"
            "3. Re-enroll Face\n"
            "4. Update MAC Address\n"
            "5. Back to main menu\n> "
        ).strip()
        if choice == "1":
            recover_totp(ssock)
        elif choice == "2":
            recover_password(ssock)
        elif choice == "3":
            recover_face(ssock)
        elif choice == "4":
            recover_mac(ssock)
        elif choice == "5":
            break
        else:
            print("Invalid option.")


# ---------------------------
# Main
# ---------------------------

BANNER = r"""
      .o         .o.                      .     oooo        
    .d88        .888.                   .o8     `888        
  .d'888       .8"888.     oooo  oooo  .o888oo   888 .oo.   
.d'  888      .8' `888.    `888  `888    888     888P"Y88b  
88ooo888oo   .88ooo8888.    888   888    888     888   888  
     888    .8'     `888.   888   888    888 .   888   888  
    o888o  o88o     o8888o  `V88V"V8P'   "888"  o888o o888o 
"""

NOTICE = r"""
--------------------------------------------------------------------------------

      Welcome to 4Auth's Login Command Line Interface:
      
      * Only Authorized Parties should attempt to access the application behind this portal

--------------------------------------------------------------------------------

"""

print(BANNER)
print(NOTICE)

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # dev/testing only

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print("Connected to", ssock.getpeername())
        while True:
            menu_input = input(
                "\nMain Menu:\n"
                "1. Log in\n"
                "2. Register Account (admin only)\n"
                "3. Recovery Options\n"
                "4. Exit\n> "
            ).strip()

            if menu_input == "1":
                print("Logging In")
                login(ssock)
            elif menu_input == "2":
                print("Registering an Account")
                register_account(ssock)
            elif menu_input == "3":
                recovery_menu(ssock)
            elif menu_input == "4":
                print("Exiting")
                break
            else:
                print("Invalid option.")
