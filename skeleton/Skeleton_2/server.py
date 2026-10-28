"""TCP record server: authenticated role checks, public verification, signed storage/audit.
Keep crypto_helpers.py beside this file. No user-defined classes; all runtime storage is .txt.
"""

import copy
import getpass
import json
import logging
import os
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes
from Crypto.Util.number import isPrime
from crypto_helpers import (
    Canonical,
    Hash_Generate,
    Hash_Check,
    Public_Fingerprint,
    Verify_Packet,
    Save_Packet,
    Read_Packet,
    Read_Text,
    Write_Text,
    Send_JSON,
    Receive_JSON,
)

BASE = Path(__file__).resolve().parent
STORE = BASE / "server_data"
HOST, PORT = "127.0.0.1", 5056
SESSION_SECONDS = 1800
STATE = {}
SESSIONS = {}
FAILED_LOGINS = {}
LOGGER = logging.getLogger("skeleton2")
PERMISSIONS = {
    "sender": {"register", "receiver_key", "submit", "list", "verify"},
    "reviewer": {"list", "verify"},
    "receiver": {"register", "list", "verify", "download"},
    "admin": {"list", "verify", "users", "logs", "audit", "tamper"},
}


def Atomic_Text(path, text, private=True):
    """Input: .txt Path, text and private flag. Write temporary .txt file then replace target.
    Output: None. Protects a single file from partial writes; server handles one request at a time.
    """
    path = Path(path)
    temporary = path.with_name(path.stem + "_temporary.txt")
    Write_Text(temporary, text, private)
    with temporary.open("r+") as stream:
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def Root_Sign(value):
    """Input: JSON value. Sign canonical bytes with server audit/storage RSA-PSS/SHA-256 key.
    Output: hex signature str. This server key is separate from sender ElGamal/receiver RSA keys.
    """
    return pss.new(STATE["root"]).sign(SHA256.new(Canonical(value))).hex()


def Root_Verify(value, signature):
    """Input: JSON value and hex signature. Verify against loaded server's root public key.
    Output: bool; altered user roles, catalog or audit snapshots cannot be accepted.
    """
    try:
        pss.new(STATE["root"].public_key()).verify(
            SHA256.new(Canonical(value)), bytes.fromhex(signature)
        )
        return True
    except (ValueError, TypeError):
        return False


def Signed_Save(name, payload):
    """Input: fixed server .txt filename and JSON payload. Sign and atomically save. Output: None."""
    Atomic_Text(
        STORE / name,
        json.dumps({"payload": payload, "signature": Root_Sign(payload)}, indent=2),
    )


def Signed_Read(path):
    """Input: signed .txt Path. Verify snapshot signature before use. Output: payload or ValueError."""
    value = json.loads(Read_Text(path))
    if not Root_Verify(value["payload"], value["signature"]):
        raise ValueError("Signed storage failed verification")
    return value["payload"]


def Audit_Read(path=None):
    """Input: optional audit-copy Path. Verify snapshot and every sequence/hash-chain link.
    Output: event list. Alteration/reordering/tail deletion fails unless an old whole signed snapshot is replayed.
    """
    events = Signed_Read(path or STORE / "audit.txt")["events"]
    previous = "0" * 64
    for number, event in enumerate(events, 1):
        body = {k: v for k, v in event.items() if k != "hash"}
        if (
            body["sequence"] != number
            or body["previous"] != previous
            or not Hash_Check(Canonical(body), event["hash"])
        ):
            raise ValueError("Audit hash chain failed verification")
        previous = event["hash"]
    return events


def Audit(actor, action, details):
    """Input: actor, event name and non-secret details. Append timestamped event and sign snapshot.
    Output: None. Never include passwords, session tokens, plaintext or private/AES keys.
    """
    events = Audit_Read()
    body = {
        "sequence": len(events) + 1,
        "previous": events[-1]["hash"] if events else "0" * 64,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "details": details,
    }
    events.append({**body, "hash": Hash_Generate(Canonical(body))})
    Signed_Save("audit.txt", {"events": events})


def Password_Verifier(password, salt):
    """Input: password str and salt hex. Run scrypt N=16384,r=8,p=1. Output: hex verifier, never password."""
    return scrypt(password.encode(), bytes.fromhex(salt), 32, N=2**14, r=8, p=1).hex()


def Credential(password, role):
    """Input: password >=8 characters and recognized role. Output: salted credential/public-key entry."""
    if not isinstance(password, str) or len(password) < 8 or role not in PERMISSIONS:
        raise ValueError(
            "Use a recognized role and password with at least eight characters"
        )
    salt = get_random_bytes(16).hex()
    return {
        "salt": salt,
        "verifier": Password_Verifier(password, salt),
        "role": role,
        "enabled": True,
        "public_key": None,
    }


def Setup(admin_password):
    """Input: first admin login password, at least eight characters. First run only.
    Create server signing keys and signed users/catalog/audit .txt files. Output: None.
    The server's private signing key is an owner-only local teaching file; no extra unlock password.
    """
    admin = Credential(admin_password, "admin")
    if STORE.exists() and any(STORE.iterdir()):
        raise ValueError("Server state already exists; load it instead")
    key = RSA.generate(2048)
    Write_Text(STORE / "signing_private_key.txt", key.export_key().decode(), True)
    Write_Text(STORE / "signing_public_key.txt", key.public_key().export_key().decode())
    STATE["root"] = key
    Signed_Save("users.txt", {"users": {"admin": admin}})
    Signed_Save("catalog.txt", {"records": {}})
    Signed_Save("audit.txt", {"events": []})
    Audit("server", "SETUP", {})


def Load_Server():
    """Input: none. Load existing server signing key, validate matching public key and signed files.
    Output: None. Accounts and records persist; old login tokens are cleared on restart.
    """
    key = RSA.import_key(Read_Text(STORE / "signing_private_key.txt"))
    if key.public_key().export_key().decode() != Read_Text(
        STORE / "signing_public_key.txt"
    ):
        raise ValueError("Backend signing-key mismatch")
    STATE["root"] = key
    SESSIONS.clear()
    Signed_Read(STORE / "users.txt")
    Audit_Read()
    Audit("server", "STARTUP", {})


def Configure_Logging():
    """Input: none. Attach local operational .txt log handler once. Output: None; excludes request bodies."""
    for handler in list(LOGGER.handlers):
        handler.close()
        LOGGER.removeHandler(handler)
    handler = logging.FileHandler(STORE / "server_log.txt", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


def Login(username, password):
    """Input: credentials received from the lab client. Verify signed users DB and scrypt; throttle repeated failures.
    Output: token, role, username; token exists only in server memory and expires after 30 minutes.
    """
    failures = FAILED_LOGINS.get(username, {"count": 0, "until": 0})
    if time.monotonic() < failures["until"]:
        raise PermissionError("Login temporarily locked; try again later")
    users = Signed_Read(STORE / "users.txt")["users"]
    user = users.get(username)
    if (
        not user
        or not user["enabled"]
        or not secrets.compare_digest(
            Password_Verifier(password, user["salt"]), user["verifier"]
        )
    ):
        failures["count"] += 1
        if failures["count"] >= 5:
            failures = {"count": 0, "until": time.monotonic() + 60}
        FAILED_LOGINS[username] = failures
        Audit(username, "LOGIN_FAILED", {})
        raise PermissionError("Invalid credentials or disabled account")
    FAILED_LOGINS.pop(username, None)
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "username": username,
        "until": time.monotonic() + SESSION_SECONDS,
    }
    Audit(username, "LOGIN", {"role": user["role"]})
    return {"token": token, "username": username, "role": user["role"]}


def Require(token, permission=None):
    """Input: opaque token and required permission. Resolve current enabled account and role server-side.
    Output: (username,user). Raise on missing/expired session, disabled account or unauthorized operation.
    """
    session = SESSIONS.get(token)
    if not session or time.monotonic() >= session["until"]:
        SESSIONS.pop(token, None)
        raise PermissionError("Session missing or expired")
    username = session["username"]
    user = Signed_Read(STORE / "users.txt")["users"].get(username)
    if not user or not user["enabled"]:
        raise PermissionError("Account disabled")
    if permission and permission not in PERMISSIONS[user["role"]]:
        Audit(username, "ACCESS_DENIED", {"operation": permission})
        raise PermissionError("Your role cannot perform this action")
    if permission not in ("audit", "logs"):
        Audit_Read()
    return username, user


def Manage_User(token, username, password=None, role=None, disable=False):
    """Input: admin token and target username; create with password/role or disable=True.
    Output: None. Signed role storage prevents raw edits; disabling invalidates target's sessions.
    """
    actor, _ = Require(token, "users")
    if not isinstance(username, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_]{0,31}", username
    ):
        raise ValueError(
            "Username must start with a letter and contain up to 32 letters/digits/underscores"
        )
    data = Signed_Read(STORE / "users.txt")
    if disable:
        if username == actor:
            raise ValueError("Cannot disable your own active admin account")
        data["users"][username]["enabled"] = False
        for session_token, session in list(SESSIONS.items()):
            if session["username"] == username:
                SESSIONS.pop(session_token)
    else:
        if username in data["users"]:
            raise ValueError("Username already exists")
        data["users"][username] = Credential(password, role)
    Signed_Save("users.txt", data)
    Audit(
        actor,
        "USER_DISABLED" if disable else "USER_CREATED",
        {"username": username, "role": role},
    )


def Register_Key(token, public):
    """Input: sender/receiver session and public key only. Bind first key to authenticated identity.
    Output: fingerprint. Existing keys cannot be silently replaced; private values are rejected.
    """
    actor, user = Require(token, "register")
    if user["role"] == "sender":
        if (
            not isinstance(public, dict)
            or set(public) != {"p", "g", "y"}
            or not all(type(v) is int for v in public.values())
        ):
            raise ValueError("Expected public ElGamal p,g,y only")
        p, g, y = public["p"], public["g"], public["y"]
        if not 256 <= p.bit_length() <= 4096:
            raise ValueError("Invalid ElGamal modulus size")
        ElGamal.construct((p, g, y))  # Library checks the basic public-key components.
        # Accept library-generated order-q groups and existing order-(p-1) groups.
        if not isPrime((p - 1) // 2) or pow(g, 2, p) == 1:
            raise ValueError("Invalid ElGamal public group")
    else:
        key = RSA.import_key(public)
        if key.has_private() or key.size_in_bits() < 2048:
            raise ValueError("Expected RSA public key of at least 2048 bits")
        public = key.public_key().export_key().decode()
    data = Signed_Read(STORE / "users.txt")
    if user["public_key"] is not None and user["public_key"] != public:
        raise ValueError("Registered key differs; restore your existing local key")
    if user["public_key"] is None:
        data["users"][actor]["public_key"] = public
        Signed_Save("users.txt", data)
        Audit(
            actor,
            "PUBLIC_KEY_REGISTERED",
            {"fingerprint": Public_Fingerprint(public, user["role"])},
        )
    return Public_Fingerprint(public, user["role"])


def Receiver_Key(token, receiver):
    """Input: sender session and receiver username. Output: registered enabled receiver's public RSA PEM."""
    Require(token, "receiver_key")
    user = Signed_Read(STORE / "users.txt")["users"].get(receiver)
    if (
        not user
        or not user["enabled"]
        or user["role"] != "receiver"
        or user["public_key"] is None
    ):
        raise ValueError(
            "Receiver must log in once to register a key before messages can be sent"
        )
    return user["public_key"]


def Catalog(actor):
    """Input: actor name. Verify signed manifest that binds IDs, recipients and complete packet digests.
    Output: catalog dict; audit detection/refuse if modified. Never trust folder names alone.
    """
    try:
        return Signed_Read(STORE / "catalog.txt")
    except (ValueError, TypeError, KeyError, OSError):
        Audit(actor, "CATALOG_TAMPER_DETECTED", {})
        raise ValueError("Catalog failed integrity checks")


def Can_Access(username, user, entry):
    """Input: authenticated name/user and catalog entry. Output: bool for record-level visibility."""
    return (
        user["role"] in ("admin", "reviewer")
        or (user["role"] == "sender" and entry["sender"] == username)
        or (user["role"] == "receiver" and entry["receiver"] == username)
    )


def Get_Entry(token, record_id, permission):
    """Input: session, record ID and permission. Enforce role plus record ownership. Output: (actor,entry)."""
    actor, user = Require(token, permission)
    catalog = Catalog(actor)
    if record_id not in catalog["records"]:
        raise ValueError("Unknown record ID")
    entry = catalog["records"][record_id]
    if not Can_Access(actor, user, entry):
        Audit(actor, "ACCESS_DENIED", {"operation": permission, "record_id": record_id})
        raise PermissionError("Record is not addressed to or owned by you")
    return actor, entry


def Check_Stored(record_id, entry, folder=None):
    """Input: ID, signed catalog entry, optional practice-copy folder. Output: verification dictionary.
    Bind packet digest and metadata to manifest and currently registered public keys; catch corrupt files.
    """
    try:
        packet = Read_Packet(folder or STORE / "records" / record_id)
        users = Signed_Read(STORE / "users.txt")["users"]
        checks = Verify_Packet(
            packet,
            users[entry["sender"]]["public_key"],
            users[entry["receiver"]]["public_key"],
        )
        metadata = packet["package"]["metadata"]
        checks["catalog"] = Hash_Check(Canonical(packet), entry["packet_digest"])
        checks["identity"] = (
            metadata["record_id"] == record_id
            and metadata["sender"] == entry["sender"]
            and metadata["receiver"] == entry["receiver"]
        )
        checks["overall"] = all(v for k, v in checks.items() if k != "overall")
        return checks
    except (ValueError, TypeError, KeyError, OSError):
        return {"overall": False, "malformed_or_missing_artifact": True}


def Submit(token, packet):
    """Input: sender session and encrypted/public packet. Validate identity, keys, signatures and ID.
    Output: accepted record ID. Store .txt artifacts under a unique ID; no plaintext/private keys received.
    """
    actor, user = Require(token, "submit")
    if set(packet) != {"package", "signature", "hash"}:
        raise ValueError("Unexpected packet fields")
    package = packet["package"]
    if set(package) != {
        "ciphertext",
        "nonce",
        "tag",
        "encrypted_key",
        "metadata",
        "sender_public",
        "receiver_public",
    }:
        raise ValueError("Unexpected encrypted package fields")
    if RSA.import_key(package["receiver_public"]).has_private():
        raise ValueError("Never upload a receiver private key")
    metadata = package["metadata"]
    rid = metadata["record_id"]
    if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rid):
        raise ValueError("Use 1..64 letters/digits/underscores/hyphens for record ID")
    if metadata["sender"] != actor or user["public_key"] is None:
        raise PermissionError("Logged-in sender must match the signed sender identity")
    users = Signed_Read(STORE / "users.txt")["users"]
    receiver = users.get(metadata["receiver"])
    if (
        not receiver
        or not receiver["enabled"]
        or receiver["role"] != "receiver"
        or receiver["public_key"] is None
    ):
        raise ValueError("Unknown/unregistered receiver")
    if not Verify_Packet(packet, user["public_key"], receiver["public_key"])["overall"]:
        Audit(actor, "SUBMISSION_REJECTED", {"record_id": rid, "reason": "integrity"})
        raise ValueError("Hash, signature, metadata or key verification failed")
    catalog = Catalog(actor)
    folder = STORE / "records" / rid
    if rid in catalog["records"] or folder.exists():
        raise ValueError("Record ID already exists; no overwriting")
    Save_Packet(packet, folder)
    entry = {
        "sender": actor,
        "receiver": metadata["receiver"],
        "packet_digest": Hash_Generate(Canonical(packet)),
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    catalog["records"][rid] = entry
    Signed_Save("catalog.txt", catalog)
    Audit(actor, "RECORD_SUBMITTED", {"record_id": rid})
    return {"record_id": rid, "accepted": True}


def List_Records(token):
    """Input: authenticated session. Output: visible IDs, metadata summary and integrity status.
    Senders see own records; receivers addressed records; admin/reviewer see all, never plaintext.
    """
    actor, user = Require(token, "list")
    records = Catalog(actor)["records"]
    result = []
    for rid, entry in records.items():
        if Can_Access(actor, user, entry):
            valid = Check_Stored(rid, entry)["overall"]
            if not valid:
                Audit(actor, "RECORD_TAMPER_DETECTED", {"record_id": rid})
            result.append(
                {
                    "record_id": rid,
                    "sender": entry["sender"],
                    "receiver": entry["receiver"],
                    "received_at": entry["received_at"],
                    "valid": valid,
                }
            )
    Audit(actor, "RECORDS_LISTED", {"count": len(result)})
    return result


def Verify_Record(token, record_id):
    """Input: authorized session and ID. Output: all public integrity checks; audit any detected tampering."""
    actor, entry = Get_Entry(token, record_id, "verify")
    checks = Check_Stored(record_id, entry)
    Audit(
        actor,
        "VERIFY_OK" if checks["overall"] else "RECORD_TAMPER_DETECTED",
        {"record_id": record_id},
    )
    return checks


def Download(token, record_id):
    """Input: receiver session and addressed ID. Verify before sending encrypted packet and trusted keys.
    Output: packet and registered verification keys. Client must verify again before decrypting locally.
    """
    actor, entry = Get_Entry(token, record_id, "download")
    if not Check_Stored(record_id, entry)["overall"]:
        Audit(actor, "RECORD_TAMPER_DETECTED", {"record_id": record_id})
        raise ValueError("Stored record failed integrity checks; download refused")
    users = Signed_Read(STORE / "users.txt")["users"]
    Audit(actor, "RECORD_DOWNLOADED", {"record_id": record_id})
    return {
        "packet": Read_Packet(STORE / "records" / record_id),
        "trusted_sender": users[entry["sender"]]["public_key"],
        "trusted_receiver": users[entry["receiver"]]["public_key"],
    }


def Tamper_Test(token, record_id, target):
    """Input: admin session, existing ID, target artifact or 'audit'. Modify only a practice copy.
    Output: expected rejection checks. Never re-sign the changed copy or damage the live original.
    """
    actor, entry = Get_Entry(token, record_id, "tamper")
    folder = STORE / "tamper_practice" / record_id
    if target == "audit":
        raw = json.loads(Read_Text(STORE / "audit.txt"))
        raw["payload"]["events"].pop()
        Atomic_Text(folder / "audit_copy.txt", json.dumps(raw))
        try:
            Audit_Read(folder / "audit_copy.txt")
            result = {"audit_valid": True}
        except (ValueError, TypeError, KeyError):
            result = {"audit_valid": False}
    else:
        packet = Read_Packet(STORE / "records" / record_id)
        Save_Packet(packet, folder)
        package = packet["package"]
        if target in ("ciphertext", "nonce", "tag", "encrypted_key"):
            data = bytearray.fromhex(package[target])
            if data:
                data[0] ^= 1
            else:
                data.append(1)
            package[target] = data.hex()
        elif target == "metadata":
            package["metadata"]["receiver"] = "CHANGED"
        elif target == "public_key":
            package["sender_public"]["y"] += 1
        elif target == "signature":
            packet["signature"]["s"] = 0
        elif target == "hash":
            packet["hash"] = "0" * 64
        else:
            raise ValueError(
                "Choose ciphertext/nonce/tag/encrypted_key/metadata/public_key/signature/hash/audit"
            )
        Save_Packet(packet, folder)
        result = Check_Stored(record_id, entry, folder)
    Audit(
        actor,
        "TAMPER_PRACTICE",
        {"record_id": record_id, "target": target, "result": result},
    )
    return result


def Audit_Report(token):
    """Input: admin session. Output: verified audit snapshot and last 100 operational log lines.
    Operational logs are diagnostic, not signed; the signed audit is the integrity-protected record.
    """
    actor, _ = Require(token, "audit")
    events = Audit_Read()
    Audit(actor, "AUDIT_VIEWED", {})
    log = (
        Read_Text(STORE / "server_log.txt")
        if (STORE / "server_log.txt").exists()
        else ""
    )
    return {
        "audit_valid": True,
        "events": events,
        "operational_log": log.splitlines()[-100:],
    }


def Dispatch(request):
    """Input: decoded JSON request dict. Route to guarded high-level operations. Output: JSON result.
    Never accept a caller-supplied role as authority, arbitrary file path, private key or decryption action.
    """
    action = request["action"]
    args = request.get("args", {})
    token = request.get("token", "")
    if action == "login":
        return Login(args["username"], args["password"])
    actor, user = Require(token)
    if action == "logout":
        SESSIONS.pop(token, None)
        Audit(actor, "LOGOUT", {})
        return "Logged out"
    if action == "profile":
        return {
            "username": actor,
            "role": user["role"],
            "public_key": user["public_key"],
        }
    if action == "register":
        return Register_Key(token, args["public_key"])
    if action == "receiver_key":
        return Receiver_Key(token, args["receiver"])
    if action == "submit":
        return Submit(token, args["packet"])
    if action == "list":
        return List_Records(token)
    if action == "verify":
        return Verify_Record(token, args["record_id"])
    if action == "download":
        return Download(token, args["record_id"])
    if action == "create_user":
        Manage_User(token, args["username"], args["password"], args["role"])
        return "User created"
    if action == "disable_user":
        Manage_User(token, args["username"], disable=True)
        return "User disabled"
    if action == "users":
        Require(token, "users")
        return [
            {"username": name, "role": entry["role"], "enabled": entry["enabled"]}
            for name, entry in Signed_Read(STORE / "users.txt")["users"].items()
        ]
    if action == "audit":
        return Audit_Report(token)
    if action == "tamper":
        return Tamper_Test(token, args["record_id"], args["target"])
    raise ValueError("Unknown operation")


def Server_Start(stop_after=None, ready=None, stop_event=None):
    """Input: none for ordinary use. Listen on localhost:5056 and handle TCP requests in a loop.
    Output: None. Optional count/events let verification stop the loop cleanly; not command-line options.
    Read JSON, dispatch to a permission-checked function, reply, close connection. Ctrl+C stops server.
    """
    Configure_Logging()
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        server.settimeout(0.5)
        print("Server listening on", HOST, PORT, flush=True)
        if ready is not None:
            ready.set()
        while (stop_after is None or count < stop_after) and not (
            stop_event and stop_event.is_set()
        ):
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(10)
                try:
                    request = Receive_JSON(connection)
                    result = Dispatch(request)
                    Send_JSON(connection, {"ok": True, "result": result})
                    LOGGER.info(
                        "Request succeeded action=%s peer=%s",
                        str(request.get("action", ""))[:40].replace("\n", ""),
                        address[0],
                    )
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    OSError,
                    EOFError,
                    PermissionError,
                    AttributeError,
                ) as error:
                    LOGGER.warning(
                        "Request refused error=%s peer=%s",
                        type(error).__name__,
                        address[0],
                    )
                    try:
                        Send_JSON(
                            connection,
                            {
                                "ok": False,
                                "error": (
                                    str(error)
                                    if isinstance(error, (PermissionError, ValueError))
                                    else "Malformed request or unavailable storage"
                                ),
                            },
                        )
                    except OSError:
                        pass
            count += 1


def Menu():
    """Input: first-run admin password only. Create/load server state and start listening immediately.
    Output: None. No certificate setup or separate operator login; Ctrl+C stops the server.
    """
    try:
        if (STORE / "signing_private_key.txt").exists():
            Load_Server()
        else:
            Setup(getpass.getpass("First run: choose admin login password: "))
            print("Created admin account: admin")
        Server_Start()
    except KeyboardInterrupt:
        print("Server stopped")
    except (ValueError, TypeError, KeyError, OSError) as error:
        print("Server operation refused:", error)


if __name__ == "__main__":
    Menu()
