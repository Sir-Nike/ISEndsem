import json
import time
import secrets
import hashlib
import hmac
import re
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512, MD5
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def ask_text(label, default=None):
    """Input: prompt and optional default. Read terminal text; Enter accepts a supplied default.
    Output: nonempty string. Use ask_text('Patient ID') when a value must be entered.
    """
    shown = f" [{default}]" if default is not None else ""
    value = input(label + shown + ": ").strip()
    if not value and default is not None:
        return str(default)
    if not value:
        raise ValueError(label + " cannot be empty.")
    return value


def canonical(record):
    """Input: JSON-compatible record. Sort keys and remove irrelevant spaces consistently.
    Output: UTF-8 bytes. Hash/sign these exact bytes so dictionary formatting cannot change results.
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def read_json(path, default=None):
    """Input: JSON file path and optional missing-file default. Parse saved records.
    Output: decoded JSON. Invalid JSON raises an error instead of silently replacing damaged data.
    """
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def save_json(path, record, secret=False):
    """Input: path, record and secret-file flag. Write via a temporary file then replace atomically.
    Output: saved JSON file; returns nothing. Secret files receive owner-only permissions.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if secret:
        import os

        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(record, stream, indent=2, ensure_ascii=False, allow_nan=False)
    else:
        temporary.write_text(json.dumps(record, indent=2, ensure_ascii=False, allow_nan=False))
    temporary.replace(path)
    if secret:
        path.chmod(0o600)


def display_time(timestamp):
    """Input: Unix seconds. Format an explicit date/time in Asia/Kolkata.
    Output: readable timestamp string. Use for key expiry, voting windows and audit displays.
    """
    return datetime.fromtimestamp(timestamp, ZoneInfo("Asia/Kolkata")).isoformat(timespec="seconds")


def cbc_encrypt(data, key):
    """Input: plaintext bytes and AES key. Generate a fresh IV, PKCS#7-pad and CBC-encrypt.
    Output: hex IV/ciphertext dictionary. Sign the envelope separately to detect modification.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    return {"iv": cipher.iv.hex(), "ciphertext": cipher.encrypt(pad(data, AES.block_size)).hex()}


def cbc_decrypt(envelope, key):
    """Input: authenticated CBC envelope and original AES key. Decrypt and remove padding.
    Output: plaintext bytes. Call only after verifying the enclosing signature/integrity checks.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex(envelope["iv"]))
    return unpad(cipher.decrypt(bytes.fromhex(envelope["ciphertext"])), AES.block_size)


def rsa_sign(private_pem, data, algorithm="sha256"):
    """Input: RSA private PEM, bytes to sign and sha256/md5/sha512 selection. Hash once and sign.
    Output: PKCS#1 v1.5 signature as hex. Private keys remain local; public keys verify.
    """
    hash_module = {"sha256": SHA256, "md5": MD5, "sha512": SHA512}[algorithm]
    return pkcs1_15.new(RSA.import_key(private_pem)).sign(hash_module.new(data)).hex()


def rsa_verify(public_pem, data, signature, algorithm="sha256"):
    """Input: trusted RSA public PEM, original bytes, signature hex and hash selection.
    Output: True if the signature matches; False for altered data, key or signature encoding.
    """
    try:
        hash_module = {"sha256": SHA256, "md5": MD5, "sha512": SHA512}[algorithm]
        pkcs1_15.new(RSA.import_key(public_pem)).verify(
            hash_module.new(data), bytes.fromhex(signature)
        )
        return True
    except (ValueError, TypeError, KeyError):
        return False


def rsa_pair(bits=2048):
    """Input: RSA modulus bits. Ask PyCryptodome to generate a fresh key pair.
    Output: dictionary of private/public PEM strings. Save the private part in a secret file.
    """
    key = RSA.generate(bits)
    return {"private": key.export_key().decode(), "public": key.publickey().export_key().decode()}


def normalize_words(text):
    """Input: description/query text. Normalize case and extract alphanumeric keywords.
    Output: sorted unique word list. Use identical normalization while indexing and searching.
    """
    return sorted(set(re.findall(r"[a-z0-9]+", text.lower())))


def token(key, text):
    """Input: secret HMAC key and already normalized lookup string. Compute deterministic keyed hash.
    Output: hex lookup token. A search computes the same token without bulk decryption.
    """
    return hmac.new(key, text.encode(), hashlib.sha256).hexdigest()


def setup_accounts(path, roles):
    """Input: account file path and role names. On first use ask for each role's new password twice.
    Output: saved salted PBKDF2 password records. Existing passwords are never silently replaced.
    """
    import getpass

    existing = read_json(path)
    if existing is not None:
        return existing
    accounts = {}
    print("First run: create separate passwords for these local lab roles:", ", ".join(roles))
    for role in roles:
        password = getpass.getpass("New password for " + role + ": ")
        if not password or password != getpass.getpass("Confirm password: "):
            raise ValueError("Passwords must be nonempty and match.")
        salt = get_random_bytes(16)
        digest = PBKDF2(password.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA256)
        accounts[role] = {"role": role, "salt": salt.hex(), "password_hash": digest.hex()}
    save_json(path, accounts, True)
    return accounts


def authenticate(accounts, username, password):
    """Input: saved accounts, username and entered password. Derive and compare the salted password hash.
    Output: role string on success; ValueError on unknown account or wrong password.
    """
    if username not in accounts:
        raise ValueError("Invalid login.")
    record = accounts[username]
    received = PBKDF2(
        password.encode(),
        bytes.fromhex(record["salt"]),
        dkLen=32,
        count=200000,
        hmac_hash_module=SHA256,
    )
    if not hmac.compare_digest(received.hex(), record["password_hash"]):
        raise ValueError("Invalid login.")
    return record["role"]


def login(accounts):
    """Input: username and hidden password from the terminal. Authenticate a previously created account.
    Output: username and assigned role; callers use that role to choose the allowed menu.
    """
    import getpass

    username = ask_text("Username")
    role = authenticate(accounts, username, getpass.getpass("Password: "))
    return username, role


def require_role(actual, allowed):
    """Input: authenticated role and allowed-role collection. Check permission inside the operation itself.
    Output: nothing on success; PermissionError on denial. Menus alone are not authorization checks.
    """
    if actual not in allowed:
        raise PermissionError("This role cannot perform that operation.")


def audit(folder, event, details, private_pem):
    """Input: audit directory, event name, details and signing key. Chain and sign a new audit entry.
    Output: appended JSONL event. The previous-entry digest exposes edits, reordering and gaps.
    """
    path = Path(folder) / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text().splitlines() if path.exists() else []
    previous = hashlib.sha256(lines[-1].encode()).hexdigest() if lines else "0" * 64
    entry = {
        "sequence": len(lines) + 1,
        "time": time.time(),
        "event": event,
        "details": details,
        "previous": previous,
    }
    entry["signature"] = rsa_sign(private_pem, canonical(entry))
    with path.open("a") as stream:
        stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def verify_audit(folder, public_pem):
    """Input: audit directory and trusted signing public key. Verify signatures and previous-entry chain.
    Output: True when existing entries are intact. External anchoring is needed to detect deletion of the final suffix.
    """
    path = Path(folder) / "audit.jsonl"
    previous = "0" * 64
    if not path.exists():
        return True
    try:
        for index, line in enumerate(path.read_text().splitlines(), 1):
            entry = json.loads(line)
            signature = entry.pop("signature")
            if (
                entry["sequence"] != index
                or entry["previous"] != previous
                or not rsa_verify(public_pem, canonical(entry), signature)
            ):
                return False
            previous = hashlib.sha256(line.encode()).hexdigest()
        return True
    except (ValueError, KeyError, TypeError):
        return False


def initialize_reports(folder):
    """Input: storage folder. Load/create RSA-2048 identity, HMAC index key and report/key registries.
    Output: keys, encrypted reports and per-record expiring keys. Persisted expiry never resets on restart.
    """
    folder.mkdir(parents=True, exist_ok=True)
    keys = read_json(folder / "system_keys.json")
    if keys is None:
        keys = {"rsa": rsa_pair(2048), "index": get_random_bytes(32).hex()}
        save_json(folder / "system_keys.json", keys, True)
    return (
        keys,
        read_json(folder / "reports.json", {"records": {}, "index": {}}),
        read_json(folder / "record_keys.json", {}),
    )


def derive_report_key(password, salt):
    """Input: entered key password and random salt bytes. Run PBKDF2-HMAC-SHA256 for exactly 10 iterations.
    Output: 24-byte AES-192 key. Ten iterations matches this exam prompt, not a real password-hardening recommendation.
    """
    if not password:
        raise ValueError("Key password cannot be empty.")
    return PBKDF2(password.encode(), salt, dkLen=24, count=10, hmac_hash_module=SHA256)


def report_payload(record):
    """Input: saved report. Remove signature field before canonical hashing/signing.
    Output: all authenticated fields, including encrypted ID/department, expiry and key commitment.
    """
    return {name: value for name, value in record.items() if name != "signature"}


def verify_report(record, record_keys, keys):
    """Input: report, current per-record key store and trusted RSA identity. Check signature and signed key binding.
    Output: details with rsa_signature, key_integrity and overall booleans. Key tampering makes overall False.
    """
    try:
        rsa_valid = rsa_verify(
            keys["rsa"]["public"], canonical(report_payload(record)), record["signature"]
        )
        entry = record_keys[record["key_id"]]
        key = bytes.fromhex(entry["key"])
        intact = (
            len(key) == 24
            and hmac.compare_digest(hashlib.sha256(key).hexdigest(), record["key_commitment"])
            and entry["issued_at"] == record["issued_at"]
            and entry["expires_at"] == record["expires_at"]
            and entry["salt"] == record["kdf_salt"]
            and entry["iterations"] == 10
            and entry["key_id"] == record["key_id"]
        )
        return {
            "rsa_signature": rsa_valid,
            "key_integrity": intact,
            "overall": rsa_valid and intact,
        }
    except (ValueError, KeyError, TypeError):
        return {"rsa_signature": False, "key_integrity": False, "overall": False}


def active_key(record, record_keys, keys, now=None):
    """Input: report, key store, system identity and optional time. Verify key binding and 120-second validity.
    Output: AES key bytes only if verified and unexpired. Every encrypt/decrypt path must enforce this check.
    """
    checks = verify_report(record, record_keys, keys)
    if not checks["overall"]:
        raise ValueError("Signature/key integrity verification failed.")
    now = time.time() if now is None else now
    if not record["issued_at"] <= now < record["expires_at"]:
        raise ValueError("Key is expired or not yet valid; it cannot be used.")
    return bytes.fromhex(record_keys[record["key_id"]]["key"])


def add_report(
    registry,
    record_keys,
    keys,
    role,
    username,
    report_id,
    department,
    description,
    password,
    now=None,
):
    """Input: staff role, report fields and derivation password. Hash description and CBC-encrypt ID/department.
    Output: signed report inserted into registry and 120-second key entry. Description plaintext is not saved.
    """
    require_role(role, ("staff",))
    if not all(value.strip() for value in (report_id, department, description)):
        raise ValueError("All report fields are required.")
    # A separate ID token prevents duplicates without decrypting old reports or exposing IDs in cleartext.
    id_token = token(bytes.fromhex(keys["index"]), "report-id:" + report_id.strip())
    if any(row["report_id_token"] == id_token for row in registry["records"].values()):
        raise ValueError("Report ID already exists.")
    now = time.time() if now is None else now
    salt = get_random_bytes(16)
    key = derive_report_key(password, salt)
    locator = secrets.token_hex(12)
    key_id = secrets.token_hex(12)
    expires = now + 120
    envelope = cbc_encrypt(
        canonical({"report_id": report_id.strip(), "department": department.strip()}), key
    )
    keywords = [
        token(bytes.fromhex(keys["index"]), "description:" + word)
        for word in normalize_words(description)
    ]
    record = {
        "locator": locator,
        "report_id_token": id_token,
        "fields": envelope,
        "description_sha256": hashlib.sha256(description.encode()).hexdigest(),
        "keywords": keywords,
        "key_id": key_id,
        "issued_at": now,
        "expires_at": expires,
        "kdf_salt": salt.hex(),
        "key_commitment": hashlib.sha256(key).hexdigest(),
        "created_by": username,
    }
    record["signature"] = rsa_sign(keys["rsa"]["private"], canonical(record))
    record_keys[key_id] = {
        "key_id": key_id,
        "key": key.hex(),
        "salt": salt.hex(),
        "iterations": 10,
        "issued_at": now,
        "expires_at": expires,
    }
    registry["records"][locator] = record
    for keyword in keywords:
        registry["index"].setdefault(keyword, []).append(locator)
    return record


def search_reports(registry, keys, role, query):
    """Input: admin role and one description keyword. Match its HMAC token in the inverted index.
    Output: opaque report locators only; no report field decryption occurs during search.
    """
    require_role(role, ("admin",))
    words = normalize_words(query)
    if len(words) != 1:
        raise ValueError("Search exactly one keyword.")
    lookup = token(bytes.fromhex(keys["index"]), "description:" + words[0])
    matches = registry["index"].get(lookup, [])
    # Match posting against each signed record's own keyword list to reject substituted index entries.
    for locator in matches:
        if (
            locator not in registry["records"]
            or lookup not in registry["records"][locator]["keywords"]
        ):
            raise ValueError("Search index tampering detected.")
        row = registry["records"][locator]
        if not rsa_verify(keys["rsa"]["public"], canonical(report_payload(row)), row["signature"]):
            raise ValueError("Matching signed record is tampered.")
    return matches


def view_report(registry, record_keys, keys, role, locator, now=None):
    """Input: admin role, one report locator and current time. Verify signature/key/expiry, then decrypt one report.
    Output: report ID, department and description hash. Expired keys are rejected even after restart.
    """
    require_role(role, ("admin",))
    record = registry["records"][locator]
    key = active_key(record, record_keys, keys, now)
    fields = json.loads(cbc_decrypt(record["fields"], key))
    fields["description_sha256"] = record["description_sha256"]
    fields["expires_at"] = display_time(record["expires_at"])
    return fields


def change_department(
    registry, record_keys, keys, role, locator, new_department, reason, folder, username
):
    """Input: admin session, record, new department and required reason. Verify current active key and old fields.
    Output: newly encrypted/signed report plus signed audit event containing before/after departments.
    """
    require_role(role, ("admin",))
    if not new_department.strip() or not reason.strip():
        raise ValueError("New department and change reason required.")
    record = registry["records"][locator]
    key = active_key(record, record_keys, keys)
    fields = json.loads(cbc_decrypt(record["fields"], key))
    old = fields["department"]
    fields["department"] = new_department.strip()
    record["fields"] = cbc_encrypt(canonical(fields), key)
    record["signature"] = rsa_sign(keys["rsa"]["private"], canonical(report_payload(record)))
    audit(
        folder,
        "department_changed",
        {
            "locator": locator,
            "old": old,
            "new": new_department.strip(),
            "reason": reason,
            "by": username,
        },
        keys["rsa"]["private"],
    )
    return record


def persist_reports(folder, registry, record_keys):
    """Input: folder, reports and expiring key entries. Save data and secret keys separately.
    Output: reports.json and owner-only record_keys.json. Never alter the original issue/expiry times.
    """
    save_json(folder / "reports.json", registry)
    save_json(folder / "record_keys.json", record_keys, True)


def verify_and_audit(folder, record, record_keys, keys, username):
    """Input: selected report and current key material. Verify and append a signed result/tamper audit event.
    Output: detailed check booleans. Changed keys yield overall False even if record bytes are unchanged.
    """
    checks = verify_report(record, record_keys, keys)
    event = "record_verified" if checks["overall"] else "tampering_detected"
    audit(
        folder,
        event,
        {"locator": record.get("locator"), "checks": checks, "by": username},
        keys["rsa"]["private"],
    )
    return checks


def role_menu(folder, keys, registry, record_keys, username, role):
    """Input: authenticated staff/admin session. Enforce role permissions and report/key expiry on operations.
    Output: encrypted reports, selected results, signature checks, expiry displays and audit records.
    """
    import getpass

    while True:
        print("\nRole:", role)
        if role == "staff":
            print("1 Add/encrypt report  2 Verify own report  0 Logout")
        else:
            print(
                "1 List encrypted reports  2 Search keyword  3 View one  4 Verify one  5 Change department"
            )
        if role == "admin":
            print(
                "6 View/verify audit  7 Simulate key tampering  8 Simulate encrypted department tampering  0 Logout"
            )
        try:
            choice = ask_text("Role choice")
            if choice == "0":
                return
            if role == "staff" and choice == "1":
                report_id = ask_text("Report ID")
                department = ask_text("Department")
                description = ask_text("Description")
                record = add_report(
                    registry,
                    record_keys,
                    keys,
                    role,
                    username,
                    report_id,
                    department,
                    description,
                    getpass.getpass("KDF password: "),
                )
                persist_reports(folder, registry, record_keys)
                audit(
                    folder,
                    "report_added",
                    {"locator": record["locator"], "by": username},
                    keys["rsa"]["private"],
                )
                print(
                    "Locator:",
                    record["locator"],
                    "Description SHA-256:",
                    record["description_sha256"],
                )
                print(
                    "RSA signature:",
                    record["signature"],
                    "Issued:",
                    display_time(record["issued_at"]),
                    "Expiry:",
                    display_time(record["expires_at"]),
                )
            elif role == "staff" and choice == "2":
                row = registry["records"][ask_text("Report locator")]
                if row["created_by"] != username:
                    raise PermissionError("Only your own reports can be verified here.")
                print("Verification:", verify_and_audit(folder, row, record_keys, keys, username))
            elif role == "admin" and choice == "1":
                for locator, row in registry["records"].items():
                    print(
                        locator,
                        "Expiry:",
                        display_time(row["expires_at"]),
                        "Active:",
                        time.time() < row["expires_at"],
                        "Encrypted fields:",
                        row["fields"],
                    )
            elif role == "admin" and choice == "2":
                print(
                    "Matching locators:",
                    search_reports(registry, keys, role, ask_text("Description keyword")),
                )
            elif role == "admin" and choice == "3":
                locator = ask_text("Locator")
                checks = verify_and_audit(
                    folder, registry["records"][locator], record_keys, keys, username
                )
                if not checks["overall"]:
                    raise ValueError("Tampered record/key; decryption refused.")
                print(json.dumps(view_report(registry, record_keys, keys, role, locator), indent=2))
            elif role == "admin" and choice == "4":
                print(
                    "Verification:",
                    verify_and_audit(
                        folder,
                        registry["records"][ask_text("Locator")],
                        record_keys,
                        keys,
                        username,
                    ),
                )
            elif role == "admin" and choice == "5":
                locator = ask_text("Locator")
                new_department = ask_text("New department")
                reason = ask_text("Reason")
                change_department(
                    registry,
                    record_keys,
                    keys,
                    role,
                    locator,
                    new_department,
                    reason,
                    folder,
                    username,
                )
                persist_reports(folder, registry, record_keys)
                print("Department changed and audited.")
            elif role == "admin" and choice == "6":
                print("Audit chain verified:", verify_audit(folder, keys["rsa"]["public"]))
                path = folder / "audit.jsonl"
                print(path.read_text() if path.exists() else "No audit events yet.")
            elif role == "admin" and choice in ("7", "8"):
                if (
                    ask_text("Intentionally damage one saved record/key? type TAMPER", "cancel")
                    != "TAMPER"
                ):
                    continue
                row = registry["records"][ask_text("Locator")]
                if choice == "7":
                    entry = record_keys[row["key_id"]]
                    data = bytearray.fromhex(entry["key"])
                    data[0] ^= 1
                    entry["key"] = data.hex()
                else:
                    data = bytearray.fromhex(row["fields"]["ciphertext"])
                    data[0] ^= 1
                    row["fields"]["ciphertext"] = data.hex()
                persist_reports(folder, registry, record_keys)
                print(
                    "After tampering:", verify_and_audit(folder, row, record_keys, keys, username)
                )
            else:
                print("Option not permitted for this role.")
        except (ValueError, KeyError, TypeError, PermissionError, OSError) as error:
            print("Rejected:", error)
            audit(
                folder,
                "operation_rejected",
                {"role": role, "reason": str(error), "by": username},
                keys["rsa"]["private"],
            )


def main():
    """Input: first-run staff/admin passwords, login credentials and operation choices.
    Output: persistent role-based report application with 120-second keys and signed tamper/change auditing.
    """
    folder = Path(__file__).resolve().parent / "storage"
    keys, registry, record_keys = initialize_reports(folder)
    accounts = setup_accounts(folder / "accounts.json", ("staff", "admin"))
    while True:
        print("\n1 Login  0 Exit")
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice == "1":
                # Reload records and keys on each login so manual key-file tampering is detected.
                keys, registry, record_keys = initialize_reports(folder)
                username, role = login(accounts)
                role_menu(folder, keys, registry, record_keys, username, role)
            else:
                print("Choose 1 or 0.")
        except (ValueError, PermissionError, OSError) as error:
            print("Rejected:", error)
            audit(folder, "login_rejected", {"reason": str(error)}, keys["rsa"]["private"])


if __name__ == "__main__":
    main()
