"""Skeleton 4: local role-based hybrid encryption. No sockets or client/server files.
Run Menu normally. All runtime keys, records, logs and audit data are separate .txt files.
"""

import hmac
import json
import logging
import math
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from phe import paillier
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.number import isPrime

BASE = Path(__file__).resolve().parent
STORE = BASE / "practice_data"
MAX_AMOUNT = 10**12
SESSION_SECONDS = 1800
STATE = {}
SESSIONS = {}
FAILED_LOGINS = {}
LOGGER = logging.getLogger("skeleton4")
PERMISSIONS = {
    "sender": {"register", "receiver_key", "submit", "list", "verify"},
    "reviewer": {"list", "search", "verify"},
    "receiver": {"register", "list", "search", "verify", "decrypt"},
    "finance": {"list", "search", "verify", "aggregate"},
    "admin": {"list", "verify", "users", "logs", "audit", "tamper"},
}


def Canonical(value):
    """Input: JSON-compatible value. Sort keys and encode consistently as UTF-8.
    Output: bytes. Use Canonical(package) identically before hashing, signing and verification.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def Write_Text(path, text, private=False):
    """Input: destination Path, text str and private flag. Save a UTF-8 .txt file.
    Output: None. Private files get owner-only permissions; public artifacts use normal permissions.
    Use Write_Text(STORE / 'identities/alice/private_key.txt', json_text, True).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix != ".txt":
        raise ValueError("All saved artifacts must use .txt")
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644
    )
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)
    if private:
        path.chmod(0o600)


def Read_Text(path):
    """Input: text-file Path. Read UTF-8 without changing its contents. Output: str or file error."""
    return Path(path).read_text(encoding="utf-8")


def Generate_Receiver_Keys(bits=2048):
    """Input: RSA modulus bits, default 2048. Generate matching receiver private/public keys together.
    Output: (private PEM str, public PEM str). Use the public key to wrap AES, private to unwrap.
    """
    key = RSA.generate(bits)
    return key.export_key().decode("ascii"), key.public_key().export_key().decode(
        "ascii"
    )


def Generate_Sender_Keys(bits=256):
    """Input: ElGamal modulus bits, default 256 for quick practice (not a production size).
    Let Crypto.PublicKey.ElGamal.generate create p,g,x,y using secure random bytes.
    Output: (private dict {p,g,x}, public dict {p,g,y}); int() makes library values JSON-compatible.
    Use Generate_Sender_Keys(2048) when the exam requires a larger modulus.
    """
    if not 256 <= bits <= 4096:
        raise ValueError("Choose ElGamal bits in 256..4096")
    key = ElGamal.generate(bits, get_random_bytes)
    return {"p": int(key.p), "g": int(key.g), "x": int(key.x)}, {
        "p": int(key.p),
        "g": int(key.g),
        "y": int(key.y),
    }


def Generate_Symmetric_Key():
    """Input: none. Generate fresh 32 random bytes. Output: AES-256 key bytes; use once per message."""
    return get_random_bytes(32)


def Encrypt(plaintext, key, aad):
    """Input: plaintext bytes, AES key bytes and metadata bytes as AAD.
    Encrypt using AES-256-GCM with fresh 12-byte nonce. Output: hex dict ciphertext/nonce/tag.
    Use Encrypt(text.encode(), key, Canonical(metadata)); caller saves all three outputs.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": ciphertext.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
    }


def Decrypt(envelope, key, aad):
    """Input: hex envelope dict, recovered AES key, identical metadata bytes.
    Verify GCM tag and decrypt. Output: authenticated plaintext bytes; ValueError on altered data.
    Never return a plaintext obtained without the tag check.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(envelope["nonce"]))
    cipher.update(aad)
    return cipher.decrypt_and_verify(
        bytes.fromhex(envelope["ciphertext"]), bytes.fromhex(envelope["tag"])
    )


def Encrypt_Key(key, receiver_public):
    """Input: AES key bytes and receiver public PEM str. RSA-OAEP/SHA-256 encrypt only that key.
    Output: encrypted key hex str. Use Encrypt_Key(key, receiver_public); not for encrypting files.
    """
    return (
        PKCS1_OAEP.new(RSA.import_key(receiver_public), hashAlgo=SHA256)
        .encrypt(key)
        .hex()
    )


def Decrypt_Key(encrypted_key, receiver_private):
    """Input: encrypted key hex str and matching receiver private PEM str.
    RSA-OAEP/SHA-256 unwraps AES key. Output: original key bytes or ValueError on failure.
    """
    return PKCS1_OAEP.new(RSA.import_key(receiver_private), hashAlgo=SHA256).decrypt(
        bytes.fromhex(encrypted_key)
    )


def DS_Sign(data, private):
    """Input: canonical package bytes and ElGamal private dict {p,g,x}.
    Public ElGamal.sign() is unimplemented; apply the signature equations here.
    Hash bytes with SHA-256; choose fresh k coprime to p-1; compute r=g^k, s=(h-x*r)/k mod p-1.
    Output: dict {r,s}. Never reuse k. Use DS_Sign(Canonical(package), sender_private).
    """
    p, g, x = private["p"], private["g"], private["x"]
    digest = int.from_bytes(SHA256.new(data).digest(), "big")
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            r = pow(g, k, p)
            s = ((digest - x * r) * pow(k, -1, p - 1)) % (p - 1)
            if s != 0:
                return {"r": r, "s": s}


def DS_Verify(data, signature, public):
    """Input: package bytes, signature {r,s}, trusted public dict {p,g,y}.
    Compare g^SHA256(data) with y^r*r^s modulo p. Output: bool; no private key/plaintext needed.
    """
    try:
        p, g, y = public["p"], public["g"], public["y"]
        r, s = signature["r"], signature["s"]
        if not (1 < g < p and 0 < y < p and 0 < r < p and 0 < s < p - 1):
            return False
        digest = int.from_bytes(SHA256.new(data).digest(), "big")
        return pow(g, digest, p) == pow(y, r, p) * pow(r, s, p) % p
    except (KeyError, TypeError, ValueError):
        return False


def Hash_Generate(data):
    """Input: bytes. Calculate SHA-256. Output: 64-character hex digest str; use on canonical package."""
    return SHA256.new(data).hexdigest()


def Hash_Check(data, expected):
    """Input: package bytes and saved hex digest. Recompute and compare. Output: bool.
    A hash alone does not authenticate data; signature verification must also succeed.
    """
    return hmac.compare_digest(Hash_Generate(data), expected)


def Public_Fingerprint(public, kind):
    """Input: public ElGamal dict or RSA PEM, and 'sender'/'receiver'. Output: SHA-256 identifier.
    RSA is normalized to DER; ElGamal uses sorted JSON. Private values must never be passed here.
    """
    data = (
        Canonical(public)
        if kind == "sender"
        else RSA.import_key(public).public_key().export_key(format="DER")
    )
    return Hash_Generate(data)


def Metadata(record_id, sender, receiver, sender_public, receiver_public, department):
    """Input: ID, two usernames and registered public keys. Output: immutable public metadata dict.
    Its identities/algorithm labels/fingerprints are covered by the signature and GCM AAD.
    """
    return {
        "record_id": record_id,
        "sender": sender,
        "receiver": receiver,
        "version": 1,
        "department": department,
        "amount_cipher": "Paillier",
        "search": "HMAC-SHA256",
        "cipher": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature": "ElGamal-SHA256",
        "hash": "SHA256",
        "sender_fingerprint": Public_Fingerprint(sender_public, "sender"),
        "receiver_fingerprint": Public_Fingerprint(receiver_public, "receiver"),
    }


def Create_Packet(
    text,
    record_id,
    sender,
    receiver,
    sender_private,
    sender_public,
    receiver_public,
    department,
    amount,
):
    """Input: description/IDs/keys, department and integer amount. Output: (signed packet,AES key).
    Encrypt description with AES/RSA and amount with Paillier; sign/hash all fields including HMAC tokens.
    """
    metadata = Metadata(
        record_id, sender, receiver, sender_public, receiver_public, department
    )
    key = Generate_Symmetric_Key()
    package = {
        **Encrypt(text.encode(), key, Canonical(metadata)),
        "encrypted_key": Encrypt_Key(key, receiver_public),
        "metadata": metadata,
        "sender_public": sender_public,
        "receiver_public": receiver_public,
        "encrypted_amount": Paillier_Encrypt(amount),
        "search_tokens": sorted(Generate_Search_Token(word) for word in Keywords(text)),
    }
    data = Canonical(package)
    return {
        "package": package,
        "signature": DS_Sign(data, sender_private),
        "hash": Hash_Generate(data),
    }, key


def Verify_Packet(packet, sender_public, receiver_public):
    """Input: packet plus independently trusted sender/receiver public keys. Output: boolean checks.
    Verify identities/metadata/signature/hash; malformed artifacts yield overall=False, never plaintext.
    """
    checks = {
        "sender_key": False,
        "receiver_key": False,
        "metadata": False,
        "signature": False,
        "hash": False,
        "amount": False,
        "tokens": False,
    }
    try:
        package = packet["package"]
        metadata = package["metadata"]
        checks["sender_key"] = package["sender_public"] == sender_public
        checks["receiver_key"] = Public_Fingerprint(
            package["receiver_public"], "receiver"
        ) == Public_Fingerprint(receiver_public, "receiver")
        checks["metadata"] = metadata == Metadata(
            metadata["record_id"],
            metadata["sender"],
            metadata["receiver"],
            sender_public,
            receiver_public,
            metadata["department"],
        )
        checks["signature"] = DS_Verify(
            Canonical(package), packet["signature"], sender_public
        )
        checks["hash"] = Hash_Check(Canonical(package), packet["hash"])
        Amount_Read(package["encrypted_amount"])
        checks["amount"] = True
        tokens = package["search_tokens"]
        checks["tokens"] = (
            isinstance(tokens, list)
            and all(
                isinstance(t, str) and re.fullmatch(r"[0-9a-f]{64}", t) for t in tokens
            )
            and tokens == sorted(set(tokens))
        )
    except (ValueError, TypeError, KeyError, OverflowError):
        pass
    checks["overall"] = all(checks.values())
    return checks


def Save_Packet(packet, folder):
    """Input: packet and destination Path. Output: None. Save each artifact separately in .txt files.
    Contains encrypted/public data, including Paillier amount and signed HMAC tokens; never plaintext.
    """
    folder = Path(folder)
    package = packet["package"]
    for name in ("ciphertext", "nonce", "tag", "encrypted_key"):
        Write_Text(folder / (name + ".txt"), package[name])
    for name in ("metadata", "sender_public", "encrypted_amount", "search_tokens"):
        Write_Text(folder / (name + ".txt"), json.dumps(package[name], indent=2))
    Write_Text(folder / "receiver_public.txt", package["receiver_public"])
    Write_Text(folder / "signature.txt", json.dumps(packet["signature"], indent=2))
    Write_Text(folder / "hash.txt", packet["hash"])


def Read_Packet(folder):
    """Input: artifact folder Path. Output: reconstructed packet; missing/malformed files raise errors."""
    folder = Path(folder)
    package = {
        name: Read_Text(folder / (name + ".txt")).strip()
        for name in ("ciphertext", "nonce", "tag", "encrypted_key")
    }
    package.update(
        {
            name: json.loads(Read_Text(folder / (name + ".txt")))
            for name in (
                "metadata",
                "sender_public",
                "encrypted_amount",
                "search_tokens",
            )
        }
    )
    package["receiver_public"] = Read_Text(folder / "receiver_public.txt")
    return {
        "package": package,
        "signature": json.loads(Read_Text(folder / "signature.txt")),
        "hash": Read_Text(folder / "hash.txt").strip(),
    }


def Atomic_Text(path, text, private=True):
    """Input: .txt Path, text and private flag. Write temporary .txt file then replace target.
    Output: None. Protects a single file from partial writes; program handles one operation at a time.
    """
    path = Path(path)
    temporary = path.with_name(path.stem + "_temporary.txt")
    Write_Text(temporary, text, private)
    with temporary.open("r+") as stream:
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def Root_Sign(value):
    """Input: JSON value. Sign canonical bytes with application audit/storage RSA-PSS/SHA-256 key.
    Output: hex signature str. This application key is separate from sender ElGamal/receiver RSA keys.
    """
    return pss.new(STATE["root"]).sign(SHA256.new(Canonical(value))).hex()


def Root_Verify(value, signature):
    """Input: JSON value and hex signature. Verify against loaded application root public key.
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
    """Input: fixed application .txt filename and JSON payload. Sign and atomically save. Output: None."""
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
    Create application signing keys, Paillier pair, HMAC key and signed users/catalog/index/audit .txt files.
    Output: None. Private Paillier factors are saved separately from public parameters.
    The application's private signing key is an owner-only local teaching file; no extra unlock password.
    """
    admin = Credential(admin_password, "admin")
    if STORE.exists() and any(STORE.iterdir()):
        raise ValueError("Application state already exists; load it instead")
    key = RSA.generate(2048)
    Write_Text(STORE / "signing_private_key.txt", key.export_key().decode(), True)
    Write_Text(STORE / "signing_public_key.txt", key.public_key().export_key().decode())
    STATE["root"] = key
    Signed_Save("users.txt", {"users": {"admin": admin}})
    Signed_Save("catalog.txt", {"records": {}})
    Signed_Save("audit.txt", {"events": []})
    public, private = Paillier_Keygen()
    Signed_Save("paillier_public_key.txt", public)
    Signed_Save("paillier_private_key.txt", private)
    Signed_Save("search_key.txt", {"key": get_random_bytes(32).hex()})
    Load_Extensions()
    Signed_Save("index.txt", {"key_id": Search_Key_ID(), "tokens": {}})
    Audit("application", "SETUP", {})


def Load_State():
    """Input: none. Load existing application signing key, validate matching public key and signed files.
    Output: None. Load public Paillier/HMAC state and verify index consistency; accounts/records persist.
    Old login tokens are cleared on restart; Paillier private factors are not loaded here.
    """
    key = RSA.import_key(Read_Text(STORE / "signing_private_key.txt"))
    if key.public_key().export_key().decode() != Read_Text(
        STORE / "signing_public_key.txt"
    ):
        raise ValueError("Application signing-key mismatch")
    STATE["root"] = key
    SESSIONS.clear()
    Signed_Read(STORE / "users.txt")
    Audit_Read()
    Load_Extensions()
    Verify_Index("application")
    Audit("application", "STARTUP", {})


def Configure_Logging():
    """Input: none. Attach local operational .txt log handler once. Output: None; excludes passwords and plaintext."""
    for handler in list(LOGGER.handlers):
        handler.close()
        LOGGER.removeHandler(handler)
    handler = logging.FileHandler(STORE / "activity_log.txt", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


def Login(username, password):
    """Input: credentials entered at login. Verify signed users DB and scrypt; throttle repeated failures.
    Output: token, role, username; token exists only in program memory and expires after 30 minutes.
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
    """Input: opaque token and required permission. Resolve current enabled account and role inside the program.
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
            "Receiver must log in once to generate/register a key before messages can be saved"
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
        user["role"] in ("admin", "reviewer", "finance")
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
    Output: accepted record ID. Store .txt artifacts under a unique ID; no plaintext is stored with public artifacts.
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
        "encrypted_amount",
        "search_tokens",
    }:
        raise ValueError("Unexpected encrypted package fields")
    if RSA.import_key(package["receiver_public"]).has_private():
        raise ValueError("Only a receiver public key belongs in the package")
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
    Verify_Index(actor)
    catalog = Catalog(actor)
    folder = STORE / "records" / rid
    if rid in catalog["records"] or folder.exists():
        raise ValueError("Record ID already exists; no overwriting")
    Save_Packet(packet, folder)
    entry = {
        "sender": actor,
        "receiver": metadata["receiver"],
        "packet_digest": Hash_Generate(Canonical(packet)),
        "department": metadata["department"],
        "received_at": datetime.now(timezone.utc).isoformat(),
    }
    catalog["records"][rid] = entry
    Signed_Save("catalog.txt", catalog)
    Update_Index(rid, package["search_tokens"])
    Audit(actor, "RECORD_SUBMITTED", {"record_id": rid})
    return {"record_id": rid, "accepted": True}


def List_Records(token):
    """Input: authenticated session. Output: visible IDs, metadata summary and integrity status.
    Senders see own records; receivers addressed records; admin/reviewer/finance see all, never plaintext.
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
                    "department": entry["department"],
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


def Tamper_Test(token, record_id, target):
    """Input: admin session, existing ID, target artifact or 'audit'. Modify only a practice copy.
    Output: expected rejection checks. Never re-sign the changed copy or damage the live original.
    """
    actor, entry = Get_Entry(token, record_id, "tamper")
    folder = STORE / "tamper_practice" / record_id
    if target == "index":
        raw = json.loads(Read_Text(STORE / "index.txt"))
        raw["payload"]["tokens"] = (
            {} if raw["payload"]["tokens"] else {"0" * 64: ["FAKE"]}
        )
        Atomic_Text(folder / "index_copy.txt", json.dumps(raw))
        try:
            Signed_Read(folder / "index_copy.txt")
            result = {"index_valid": True}
        except (ValueError, TypeError, KeyError):
            result = {"index_valid": False}
        Audit(
            actor,
            "TAMPER_PRACTICE",
            {"record_id": record_id, "target": target, "result": result},
        )
        return result
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
        elif target == "amount":
            package["encrypted_amount"]["ciphertext"] = "1"
        elif target == "tokens":
            package["search_tokens"] = [] if package["search_tokens"] else ["0" * 64]
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
        Read_Text(STORE / "activity_log.txt")
        if (STORE / "activity_log.txt").exists()
        else ""
    )
    return {
        "audit_valid": True,
        "events": events,
        "operational_log": log.splitlines()[-100:],
    }


def User_Folder(username):
    """Input: account username. Validate safe characters. Output: local identity directory Path.
    A username cannot select an arbitrary disk path; only letters/digits/underscore are accepted.
    """
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", username):
        raise ValueError("Invalid username")
    return STORE / "identities" / username


def Ensure_User_Keys(token):
    """Input: sender/receiver login token. Generate/load that user's matching key pair and register public.
    Output: public key. First login creates sender ElGamal or receiver RSA keys in separate .txt files.
    Existing registered keys with missing private files must be restored, never silently replaced.
    """
    username, user = Require(token, "register")
    folder = User_Folder(username)
    private_path, public_path = folder / "private_key.txt", folder / "public_key.txt"
    if private_path.exists() != public_path.exists():
        raise ValueError("Incomplete identity keys; restore missing file")
    if not private_path.exists():
        if user["public_key"] is not None:
            raise ValueError(
                "Identity already registered: restore its original private key"
            )
        if user["role"] == "sender":
            private, public = Generate_Sender_Keys()
            Write_Text(private_path, json.dumps(private, indent=2), True)
            Write_Text(public_path, json.dumps(public, indent=2))
        else:
            private, public = Generate_Receiver_Keys()
            Write_Text(private_path, private, True)
            Write_Text(public_path, public)
    if user["role"] == "sender":
        private = json.loads(Read_Text(private_path))
        public = json.loads(Read_Text(public_path))
        expected = {
            "p": private["p"],
            "g": private["g"],
            "y": pow(private["g"], private["x"], private["p"]),
        }
        if public != expected:
            raise ValueError("Sender public/private key mismatch")
    else:
        private = RSA.import_key(Read_Text(private_path))
        public = Read_Text(public_path)
        if (
            private.public_key().export_key()
            != RSA.import_key(public).public_key().export_key()
        ):
            raise ValueError("Receiver public/private key mismatch")
    Register_Key(token, public)
    return public


def Save_Message(token, receiver, record_id, department, description, amount):
    """Input: sender token, receiver, unique ID, department, secret description, nonnegative int amount.
    Output: acceptance dict. Encrypt all sensitive fields, create tokens, sign/store/catalog/index/audit.
    """
    actor, user = Require(token, "submit")
    if not isinstance(record_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}", record_id
    ):
        raise ValueError("Use a unique ID of 1..64 letters/digits/underscores/hyphens")
    if not department.strip() or not description.strip():
        raise ValueError("Department and description cannot be empty")
    Verify_Index(actor)
    public = Receiver_Key(token, receiver)
    private = json.loads(Read_Text(User_Folder(actor) / "private_key.txt"))
    packet, key = Create_Packet(
        description,
        record_id,
        actor,
        receiver,
        private,
        user["public_key"],
        public,
        department,
        amount,
    )
    result = Submit(token, packet)
    Write_Text(User_Folder(actor) / "symmetric_key.txt", key.hex(), True)
    LOGGER.info("SAVE actor=%s record=%s", actor, record_id)
    return result


def Decrypt_Record(token, record_id):
    """Input: receiver login token and addressed record ID. Check ownership/hash/signature/metadata.
    Output: plaintext str after RSA key unwrapping and GCM authentication; no plaintext is stored.
    Refuse unauthorized/tampered records; audit successful decryption or cryptographic rejection.
    """
    actor, entry = Get_Entry(token, record_id, "decrypt")
    checks = Check_Stored(record_id, entry)
    if not checks["overall"]:
        Audit(actor, "RECORD_TAMPER_DETECTED", {"record_id": record_id})
        raise ValueError("Verification failed; decryption refused")
    packet = Read_Packet(STORE / "records" / record_id)
    try:
        private = Read_Text(User_Folder(actor) / "private_key.txt")
        key = Decrypt_Key(packet["package"]["encrypted_key"], private)
        text = Decrypt(
            packet["package"], key, Canonical(packet["package"]["metadata"])
        ).decode("utf-8")
    except (ValueError, TypeError, KeyError, OSError) as error:
        Audit(
            actor,
            "DECRYPT_REJECTED",
            {"record_id": record_id, "reason": "key/tag/file"},
        )
        raise ValueError(
            "Decryption failed: key, tag or private file is invalid"
        ) from error
    Audit(actor, "DECRYPT_OK", {"record_id": record_id})
    LOGGER.info("DECRYPT actor=%s record=%s", actor, record_id)
    return text


def Logout(token):
    """Input: active login token. Remove session and audit logout. Output: None; old token stops working."""
    actor, _ = Require(token)
    SESSIONS.pop(token, None)
    Audit(actor, "LOGOUT", {})


def Manage_Users(token):
    """Input: admin token and submenu input. Create/disable/list users using guarded functions.
    Output: printed results; roles and password verifiers remain in signed users.txt.
    """
    Require(token, "users")
    print("1 Create user\n2 Disable user\n3 List users\n0 Back")
    choice = input("Action: ").strip()
    if choice == "1":
        username = input("Username: ").strip()
        role = input("Role (sender/reviewer/receiver/finance/admin): ").strip()
        password = input("New user's password: ")
        Manage_User(token, username, password, role)
        print("User created")
    elif choice == "2":
        Manage_User(token, input("Username to disable: ").strip(), disable=True)
        print("User disabled")
    elif choice == "3":
        users = Signed_Read(STORE / "users.txt")["users"]
        print(
            json.dumps(
                [
                    {"username": name, "role": user["role"], "enabled": user["enabled"]}
                    for name, user in users.items()
                ],
                indent=2,
            )
        )


def Role_Menu(token):
    """Input: login token/menu choices. Explicit search options for reviewer/receiver/finance.
    Output: None; call guarded local functions. All prompts use normal input(); no sockets.
    """
    while True:
        actor, user = Require(token)
        role = user["role"]
        if role == "sender":
            print("\n1 Enter and save record\n2 View my submissions\n0 Logout")
        elif role == "reviewer":
            print("\n1 View records\n2 Search by keyword\n3 Verify record\n0 Logout")
        elif role == "receiver":
            print(
                "\n1 View received records\n2 Search by keyword\n3 Verify and decrypt description\n0 Logout"
            )
        elif role == "finance":
            print(
                "\n1 View permitted records\n2 Search by keyword\n3 Verify and calculate encrypted total\n0 Logout"
            )
        else:
            print(
                "\n1 Manage users\n2 View logs and verify audit\n3 Tamper with a practice record\n0 Logout"
            )
        choice = input("Choice: ").strip()
        try:
            if choice == "0":
                Logout(token)
                return
            if role == "sender":
                if choice == "1":
                    receiver = input("Receiver username: ").strip()
                    rid = input("Unique record ID: ").strip()
                    department = input("Department: ").strip()
                    description = input("Secret description: ")
                    amount = int(input("Nonnegative integer amount: "))
                    print(
                        Save_Message(
                            token, receiver, rid, department, description, amount
                        )
                    )
                elif choice == "2":
                    print(json.dumps(List_Records(token), indent=2))
                else:
                    raise ValueError("Choose a displayed option")
            elif role in ("reviewer", "receiver", "finance"):
                if choice == "1":
                    print(json.dumps(List_Records(token), indent=2))
                elif choice == "2":
                    print(
                        json.dumps(
                            Search(token, input("One keyword: ").strip()), indent=2
                        )
                    )
                elif choice == "3":
                    if role == "reviewer":
                        print(Verify_Record(token, input("Record ID: ").strip()))
                    elif role == "receiver":
                        print(
                            "Recovered description:",
                            Decrypt_Record(token, input("Record ID: ").strip()),
                        )
                    else:
                        ids = [
                            part.strip()
                            for part in input("Record IDs separated by commas: ").split(
                                ","
                            )
                        ]
                        print(json.dumps(Aggregate_Total(token, ids), indent=2))
                else:
                    raise ValueError("Choose a displayed option")
            else:
                if choice == "1":
                    Manage_Users(token)
                elif choice == "2":
                    print(json.dumps(Audit_Report(token), indent=2))
                elif choice == "3":
                    rid = input("Record ID to copy: ").strip()
                    target = input(
                        "Target (ciphertext/nonce/tag/encrypted_key/metadata/public_key/signature/hash/audit/amount/tokens/index): "
                    ).strip()
                    print(Tamper_Test(token, rid, target))
                else:
                    raise ValueError("Choose a displayed option")
            LOGGER.info("ACTION actor=%s role=%s choice=%s", actor, role, choice[:10])
        except (
            ValueError,
            PermissionError,
            TypeError,
            KeyError,
            OSError,
            OverflowError,
        ) as error:
            LOGGER.warning("REFUSED actor=%s error=%s", actor, type(error).__name__)
            print("Operation refused:", error)


def Menu():
    """Input: first-run admin password, later login credentials and role choices. Output: None.
    Create/load persistent state, log in, auto-create account keys if needed, then open role menu.
    No sockets, separate processes, manual crypto menus or command-line flags are involved.
    """
    try:
        if (STORE / "signing_private_key.txt").exists():
            Load_State()
        else:
            Setup(input("First run: choose admin password (8+ characters): "))
            print("Created admin account: admin")
        Configure_Logging()
    except (ValueError, TypeError, KeyError, OSError) as error:
        print("Initialization refused:", error)
        return
    while True:
        print("\n1 Login\n0 Exit")
        choice = input("Choice: ").strip()
        if choice == "0":
            return
        if choice != "1":
            print("Choose a displayed option")
            continue
        token = None
        try:
            session = Login(input("Username: ").strip(), input("Password: "))
            token = session["token"]
            if session["role"] in ("sender", "receiver"):
                Ensure_User_Keys(token)
            Role_Menu(token)
        except (ValueError, PermissionError, TypeError, KeyError, OSError) as error:
            print("Operation refused:", error)
        finally:
            if token in SESSIONS:
                try:
                    Logout(token)
                except (ValueError, PermissionError, KeyError, OSError):
                    SESSIONS.pop(token, None)


def Paillier_Keygen(bits=2048):
    """Input: modulus bits, default 2048. Use phe's public key-generation API.
    Output: (public dict {n}, private dict {p,q}); decimal strings are safe to store in .txt JSON.
    """
    public, private = paillier.generate_paillier_keypair(n_length=bits)
    return {"n": str(public.n)}, {"p": str(private.p), "q": str(private.q)}


def Paillier_Public():
    """Input: none. Return the public library key loaded at startup. Output: PaillierPublicKey.
    Does not load private factors; needed for encryption and encrypted arithmetic only.
    """
    return STATE["paillier_public"]


def Paillier_Key_ID():
    """Input: none. Hash public modulus. Output: fingerprint str binding amounts to the active key."""
    return Hash_Generate(Canonical({"n": str(Paillier_Public().n)}))


def Amount_Read(value):
    """Input: encrypted amount dict. Validate key ID, exponent and ciphertext group before rebuilding.
    Output: phe EncryptedNumber; no decryption. Integer amounts must have exponent zero.
    """
    public = Paillier_Public()
    if (
        set(value) != {"ciphertext", "exponent", "key_id"}
        or value["key_id"] != Paillier_Key_ID()
    ):
        raise ValueError("Paillier key/amount format mismatch")
    if type(value["exponent"]) is not int or value["exponent"] != 0:
        raise ValueError("Only integer amount ciphertexts are supported")
    ciphertext = int(value["ciphertext"])
    if not 0 < ciphertext < public.nsquare or math.gcd(ciphertext, public.n) != 1:
        raise ValueError("Invalid Paillier ciphertext")
    return paillier.EncryptedNumber(public, ciphertext, exponent=0)


def Amount_Write(value):
    """Input: library EncryptedNumber. Output: text-safe ciphertext/exponent/key-ID dict.
    ciphertext() uses library re-randomization before exposing homomorphic results.
    """
    return {
        "ciphertext": str(value.ciphertext()),
        "exponent": value.exponent,
        "key_id": Paillier_Key_ID(),
    }


def Paillier_Encrypt(amount):
    """Input: int amount from zero through MAX_AMOUNT. Encrypt with fresh library randomness.
    Output: encrypted amount dict. No plaintext amount is stored in the record or audit.
    """
    if type(amount) is not int or not 0 <= amount <= min(
        MAX_AMOUNT, Paillier_Public().max_int
    ):
        raise ValueError("Amount must be an integer from 0 to " + str(MAX_AMOUNT))
    return Amount_Write(Paillier_Public().encrypt(amount))


def Paillier_Add(amounts):
    """Input: nonempty list of encrypted amount dicts with same key. Add library encrypted values.
    Output: encrypted aggregate dict. This is ciphertext multiplication mod n^2; never decrypts inputs.
    """
    if not amounts:
        raise ValueError("Select at least one record")
    total = Amount_Read(amounts[0])
    for value in amounts[1:]:
        total = total + Amount_Read(value)
    return Amount_Write(total)


def Paillier_Decrypt(encrypted_total):
    """Input: aggregate amount dict. Load signed private factors only inside finance aggregation.
    Output: integer total. Internal primitive; Aggregate_Total enforces role before calling it once.
    """
    private = Signed_Read(STORE / "paillier_private_key.txt")
    public = Paillier_Public()
    if int(private["p"]) * int(private["q"]) != public.n:
        raise ValueError("Paillier public/private key mismatch")
    key = paillier.PaillierPrivateKey(public, int(private["p"]), int(private["q"]))
    return key.decrypt(Amount_Read(encrypted_total))


def Keywords(description):
    """Input: description str. Casefold and split alphanumeric words; remove duplicates.
    Output: sorted normalized keyword list, only kept temporarily during record creation/search.
    """
    return sorted(set(re.findall(r"[^\W_]+", description.casefold(), flags=re.UNICODE)))


def Generate_Search_Token(keyword):
    """Input: one normalized keyword. HMAC-SHA256 under the independent search secret.
    Output: hex token for exact keyword matching. Use through authenticated Search, never return key.
    """
    return HMAC.new(
        STATE["search_key"], b"keyword-v1:" + keyword.encode(), digestmod=SHA256
    ).hexdigest()


def Search_Key_ID():
    """Input: none. Fingerprint random search key to bind the signed index to it. Output: hex str."""
    return Hash_Generate(STATE["search_key"])


def Load_Extensions():
    """Input: none. Verify/load public Paillier parameters and signed private HMAC-key file.
    Output: None; startup state gains public key and search key, not Paillier private factors.
    """
    public = Signed_Read(STORE / "paillier_public_key.txt")
    STATE["paillier_public"] = paillier.PaillierPublicKey(int(public["n"]))
    STATE["search_key"] = bytes.fromhex(Signed_Read(STORE / "search_key.txt")["key"])
    if len(STATE["search_key"]) != 32:
        raise ValueError("Invalid search key")


def Update_Index(record_id, tokens):
    """Input: newly stored record ID and signed token list. Add token-to-ID postings and sign index.
    Output: None. Internal persistence helper called after Submit validates the complete record.
    """
    index = Signed_Read(STORE / "index.txt")
    if index["key_id"] != Search_Key_ID():
        raise ValueError("Index search-key binding failed")
    for token in tokens:
        index["tokens"].setdefault(token, []).append(record_id)
    Signed_Save("index.txt", index)


def Verify_Index(actor):
    """Input: authenticated actor name for audit. Check signed index and rebuild postings from signed
    record token lists without decrypting descriptions. Output: verified index; refuse corruption.
    """
    try:
        index = Signed_Read(STORE / "index.txt")
        records = Catalog(actor)["records"]
        expected = {}
        for rid, entry in records.items():
            if not Check_Stored(rid, entry)["overall"]:
                raise ValueError("Record integrity failed while checking index")
            for token in Read_Packet(STORE / "records" / rid)["package"][
                "search_tokens"
            ]:
                expected.setdefault(token, []).append(rid)
        normalized = {token: sorted(ids) for token, ids in index["tokens"].items()}
        if index["key_id"] != Search_Key_ID() or normalized != {
            token: sorted(ids) for token, ids in expected.items()
        }:
            raise ValueError("Index postings do not match signed records")
        return index
    except (ValueError, TypeError, KeyError, OSError) as error:
        Audit(actor, "INDEX_TAMPER_DETECTED", {})
        raise ValueError(
            "Search index or indexed records failed verification"
        ) from error


def Search(token, keyword):
    """Input: reviewer/receiver/finance session and one keyword. Validate index, generate HMAC token,
    find IDs, filter by role/recipient and return metadata. Output: list; no description/amount decryption.
    """
    actor, user = Require(token, "search")
    words = Keywords(keyword)
    if len(words) != 1:
        raise ValueError("Enter exactly one keyword")
    index = Verify_Index(actor)
    records = Catalog(actor)["records"]
    ids = index["tokens"].get(Generate_Search_Token(words[0]), [])
    result = [
        {
            "record_id": rid,
            "sender": records[rid]["sender"],
            "receiver": records[rid]["receiver"],
            "department": records[rid]["department"],
        }
        for rid in ids
        if Can_Access(actor, user, records[rid])
    ]
    Audit(actor, "SEARCH", {"matches": len(result)})
    return result


def Aggregate_Total(token, record_ids):
    """Input: finance session and distinct selected IDs. Verify ownership/signatures/hash/catalog/key.
    Homomorphically add ciphertexts, decrypt only the final aggregate once. Output: IDs, encrypted total,total.
    Query selection is audited; single/overlapping queries can reveal individual amounts (not threshold privacy).
    """
    actor, _ = Require(token, "aggregate")
    if not record_ids or len(record_ids) != len(set(record_ids)):
        raise ValueError("Select distinct record IDs; duplicates are refused")
    if len(record_ids) * MAX_AMOUNT > Paillier_Public().max_int:
        raise ValueError("Selected total could overflow Paillier integer encoding")
    amounts = []
    for rid in record_ids:
        _, entry = Get_Entry(token, rid, "aggregate")
        if not Check_Stored(rid, entry)["overall"]:
            Audit(actor, "AGGREGATE_REJECTED", {"record_id": rid})
            raise ValueError("Selected record failed verification: " + rid)
        amounts.append(
            Read_Packet(STORE / "records" / rid)["package"]["encrypted_amount"]
        )
    encrypted_total = Paillier_Add(amounts)
    total = Paillier_Decrypt(encrypted_total)
    if not 0 <= total <= len(record_ids) * MAX_AMOUNT:
        raise ValueError("Decrypted total outside permitted amount bounds")
    Audit(actor, "AGGREGATE_OK", {"record_ids": record_ids, "count": len(record_ids)})
    return {
        "record_ids": record_ids,
        "encrypted_total": encrypted_total,
        "total": total,
    }


if __name__ == "__main__":
    Menu()
