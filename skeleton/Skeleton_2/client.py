"""Role-based TCP client; signing and decryption happen here, not on the server.
Keep crypto_helpers.py beside this file. Run Menu() normally; all saved artifacts are .txt.
"""

import getpass
import json
import re
import socket
from pathlib import Path
from Crypto.PublicKey import RSA
from crypto_helpers import (
    Canonical,
    Generate_Sender_Keys,
    Generate_Receiver_Keys,
    Create_Packet,
    Verify_Packet,
    Decrypt_Key,
    Decrypt,
    Save_Packet,
    Read_Text,
    Write_Text,
    Public_Fingerprint,
    Send_JSON,
    Receive_JSON,
)

BASE = Path(__file__).resolve().parent
STORE = BASE / "client_data"
HOST, PORT = "127.0.0.1", 5056


def Client(action, args=None, token=None):
    """Input: operation name, argument dict and optional login token.
    Open a normal TCP connection, send JSON request, read JSON reply. Output: result or ValueError.
    Use Client('list', token=session['token']). The same framing works for every menu operation.
    """
    with socket.create_connection((HOST, PORT), timeout=10) as connection:
        Send_JSON(connection, {"action": action, "args": args or {}, "token": token})
        reply = Receive_JSON(connection)
    if not reply["ok"]:
        raise ValueError(reply["error"])
    return reply["result"]


def User_Folder(username):
    """Input: authenticated username. Validate safe directory name. Output: per-user local Path."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", username):
        raise ValueError("Invalid username")
    return STORE / username


def Validate_ID(record_id):
    """Input: record ID str. Restrict it to 1..64 letters/digits/underscore/hyphen. Output: same ID."""
    if not isinstance(record_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}", record_id
    ):
        raise ValueError("Use 1..64 letters/digits/underscores/hyphens for record ID")
    return record_id


def Ensure_Local_Keys(session):
    """Input: logged-in session dict. Generate sender ElGamal or receiver RSA pair on first use.
    Output: public key or None for noncrypto roles. Bind registration to logged-in user, never upload private.
    Registered identities with missing/mismatched local keys are refused instead of silently replaced.
    """
    profile = Client("profile", token=session["token"])
    role = profile["role"]
    if role not in ("sender", "receiver"):
        return None
    folder = User_Folder(profile["username"]) / "keys"
    private_path, public_path = folder / "private_key.txt", folder / "public_key.txt"
    if private_path.exists() != public_path.exists():
        raise ValueError("Incomplete local key pair; restore the missing key")
    if not private_path.exists():
        if profile["public_key"] is not None:
            raise ValueError(
                "Account already has a key: restore its local private key instead of generating another"
            )
        if role == "sender":
            private, public = Generate_Sender_Keys()
            Write_Text(private_path, json.dumps(private, indent=2), True)
            Write_Text(public_path, json.dumps(public, indent=2))
        else:
            private, public = Generate_Receiver_Keys()
            Write_Text(private_path, private, True)
            Write_Text(public_path, public)
    if role == "sender":
        private = json.loads(Read_Text(private_path))
        public = json.loads(Read_Text(public_path))
        if public != {
            "p": private["p"],
            "g": private["g"],
            "y": pow(private["g"], private["x"], private["p"]),
        }:
            raise ValueError("Local sender public/private key mismatch")
    else:
        private = RSA.import_key(Read_Text(private_path))
        public = Read_Text(public_path)
        if (
            private.public_key().export_key()
            != RSA.import_key(public).public_key().export_key()
        ):
            raise ValueError("Local receiver public/private key mismatch")
    fingerprint = Client("register", {"public_key": public}, session["token"])
    print("Local identity ready. Public fingerprint:", fingerprint)
    return public


def Pin_Public(session, username, kind, public):
    """Input: session, other username, sender/receiver kind, registered public key from the lab server.
    Output: public key. Save .txt trust copy on first use; reject later unexpected fingerprint changes.
    Initial registry trust depends on the authenticated server and account-registration process.
    """
    User_Folder(username)
    path = (
        User_Folder(session["username"])
        / "trusted_keys"
        / (username + "_" + kind + "_public.txt")
    )
    if path.exists():
        old = json.loads(Read_Text(path)) if kind == "sender" else Read_Text(path)
        if Public_Fingerprint(old, kind) != Public_Fingerprint(public, kind):
            raise ValueError(
                "Previously trusted public key changed; ask the operator to investigate"
            )
    else:
        Write_Text(path, json.dumps(public, indent=2) if kind == "sender" else public)
    return public


def Send_Message(session, receiver, record_id, plaintext):
    """Input: sender session, receiver username, unique ID and plaintext str.
    Output: acceptance response. Encrypt/hash/sign locally, save .txt artifacts, upload only public package.
    Saved sender symmetric key is private practice material, never sent to server/receiver/reviewer.
    """
    Validate_ID(record_id)
    folder = User_Folder(session["username"])
    if (folder / "outbox" / record_id).exists():
        raise ValueError("Local record ID already used; choose a new unique ID")
    public = Client("receiver_key", {"receiver": receiver}, session["token"])
    Pin_Public(session, receiver, "receiver", public)
    private = json.loads(Read_Text(folder / "keys/private_key.txt"))
    sender_public = json.loads(Read_Text(folder / "keys/public_key.txt"))
    packet, key = Create_Packet(
        plaintext,
        record_id,
        session["username"],
        receiver,
        private,
        sender_public,
        public,
    )
    Write_Text(folder / "keys/symmetric_key.txt", key.hex(), True)
    Save_Packet(packet, folder / "outbox" / record_id)
    return Client("submit", {"packet": packet}, session["token"])


def Receive_Message(session, record_id):
    """Input: receiver session and addressed record ID. Download, pin/check identities, verify locally.
    Output: plaintext str only after local RSA unwrap and GCM authentication. Server never sees this text.
    Save encrypted artifacts only; neither recovered plaintext nor recovered AES key is saved.
    """
    Validate_ID(record_id)
    downloaded = Client("download", {"record_id": record_id}, session["token"])
    packet = downloaded["packet"]
    metadata = packet["package"]["metadata"]
    if (
        metadata["record_id"] != record_id
        or metadata["receiver"] != session["username"]
    ):
        raise ValueError("Downloaded record identity/address mismatch")
    sender_public = Pin_Public(
        session, metadata["sender"], "sender", downloaded["trusted_sender"]
    )
    folder = User_Folder(session["username"])
    receiver_public = Read_Text(folder / "keys/public_key.txt")
    if Public_Fingerprint(
        downloaded["trusted_receiver"], "receiver"
    ) != Public_Fingerprint(receiver_public, "receiver"):
        raise ValueError("Registered receiver key differs from local key")
    checks = Verify_Packet(packet, sender_public, receiver_public)
    print("Local verification:", checks)
    if not checks["overall"]:
        raise ValueError("Local verification failed; decryption refused")
    Save_Packet(packet, folder / "inbox" / record_id)
    private = Read_Text(folder / "keys/private_key.txt")
    key = Decrypt_Key(packet["package"]["encrypted_key"], private)
    return Decrypt(packet["package"], key, Canonical(metadata)).decode("utf-8")


def Manage_Users(session):
    """Input: admin session and submenu prompts. Create/disable/list accounts through guarded server API.
    Output: printed status. This small submenu keeps the main admin menu to three actions.
    """
    print("1 Create user\n2 Disable user\n3 List users\n0 Back")
    action = input("Action: ").strip()
    if action == "1":
        username = input("New username: ").strip()
        role = input("Role (sender/reviewer/receiver/admin): ").strip()
        password = getpass.getpass("New user's password: ")
        print(
            Client(
                "create_user",
                {"username": username, "role": role, "password": password},
                session["token"],
            )
        )
    elif action == "2":
        print(
            Client(
                "disable_user",
                {"username": input("Username to disable: ").strip()},
                session["token"],
            )
        )
    elif action == "3":
        print(json.dumps(Client("users", token=session["token"]), indent=2))


def Role_Menu(session):
    """Input: authenticated session. Dispatch compact sender/reviewer/receiver/admin menu.
    Output: None. Server independently checks every permission; menu choice does not grant authority.
    """
    role = session["role"]
    while True:
        if role == "sender":
            print("\n1 Enter and send message\n2 View my submissions\n0 Logout")
        elif role == "reviewer":
            print("\n1 View records\n2 Verify record\n0 Logout")
        elif role == "receiver":
            print("\n1 View received messages\n2 Verify and decrypt message\n0 Logout")
        else:
            print(
                "\n1 Manage users\n2 View logs and verify audit\n3 Tamper with a practice record\n0 Logout"
            )
        choice = input("Choice: ").strip()
        try:
            if choice == "0":
                print(Client("logout", token=session["token"]))
                return
            if role == "sender":
                if choice == "1":
                    receiver = input("Receiver username: ").strip()
                    rid = input("Unique record ID: ").strip()
                    print(Send_Message(session, receiver, rid, input("Plaintext: ")))
                elif choice == "2":
                    print(json.dumps(Client("list", token=session["token"]), indent=2))
                else:
                    raise ValueError("Choose a displayed option")
            elif role == "reviewer":
                if choice == "1":
                    print(json.dumps(Client("list", token=session["token"]), indent=2))
                elif choice == "2":
                    print(
                        Client(
                            "verify",
                            {"record_id": input("Record ID: ").strip()},
                            session["token"],
                        )
                    )
                else:
                    raise ValueError("Choose a displayed option")
            elif role == "receiver":
                if choice == "1":
                    print(json.dumps(Client("list", token=session["token"]), indent=2))
                elif choice == "2":
                    print(
                        "Recovered plaintext:",
                        Receive_Message(session, input("Record ID: ").strip()),
                    )
                else:
                    raise ValueError("Choose a displayed option")
            else:
                if choice == "1":
                    Manage_Users(session)
                elif choice == "2":
                    print(json.dumps(Client("audit", token=session["token"]), indent=2))
                elif choice == "3":
                    rid = input("Record ID to copy: ").strip()
                    target = input(
                        "Target (ciphertext/nonce/tag/encrypted_key/metadata/public_key/signature/hash/audit): "
                    ).strip()
                    print(
                        Client(
                            "tamper",
                            {"record_id": rid, "target": target},
                            session["token"],
                        )
                    )
                else:
                    raise ValueError("Choose a displayed option")
        except (ValueError, TypeError, KeyError, OSError, EOFError) as error:
            print("Operation refused:", error)
            if "Session missing or expired" in str(error) or "Account disabled" in str(
                error
            ):
                return


def Client_Start():
    """Input: none. Start interactive client by calling Menu. Output: None; no special run flags."""
    Menu()


def Menu():
    """Input: login choices and hidden credentials. Login, auto-setup local keys, open role menu.
    Output: None. Logins/passwords/tokens are not written to client files or operational logs.
    """
    while True:
        print("\n1 Login\n0 Exit")
        choice = input("Choice: ").strip()
        if choice == "0":
            return
        if choice != "1":
            print("Choose a displayed option")
            continue
        session = None
        try:
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            session = Client("login", {"username": username, "password": password})
            Ensure_Local_Keys(session)
            Role_Menu(session)
        except (ValueError, TypeError, KeyError, OSError, EOFError) as error:
            print("Client operation refused:", error)
            if session is not None:
                try:
                    Client("logout", token=session["token"])
                except (ValueError, OSError):
                    pass


if __name__ == "__main__":
    Client_Start()
