import json
import math
import time
import secrets
import hashlib
import hmac
from pathlib import Path
from decimal import Decimal, InvalidOperation
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512, MD5
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime


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


def parse_amount(text):
    """Input: money text with up to two decimal places. Convert exactly into integer paise.
    Output: nonnegative integer. Reject fractional paise, nonfinite values and negatives.
    """
    amount = Decimal(text)
    scaled = amount * 100
    if not amount.is_finite() or amount < 0 or scaled != scaled.to_integral_value():
        raise ValueError("Use a nonnegative amount with at most two decimal places.")
    return int(scaled)


def format_amount(paise):
    """Input: integer paise. Convert to a two-decimal display without floating-point rounding.
    Output: string such as 125.50. Use after decrypting a final monetary total.
    """
    return f"{paise//100}.{paise%100:02d}"


def seal(data, key):
    """Input: plaintext bytes and 16/24/32-byte AES key. Encrypt/authenticate using GCM.
    Output: JSON-safe nonce/ciphertext/tag dictionary. Save all three for verified decryption.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return {"nonce": cipher.nonce.hex(), "ciphertext": encrypted.hex(), "tag": tag.hex()}


def open_seal(envelope, key):
    """Input: saved AES-GCM envelope and matching key. Verify the tag before returning data.
    Output: plaintext bytes; wrong keys/modified ciphertext raise ValueError.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(envelope["nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(envelope["ciphertext"]), bytes.fromhex(envelope["tag"])
    )


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


def paillier_keys(bits=512):
    """Input: demonstration modulus size. Generate distinct primes and g=n+1 Paillier keys.
    Output: public n/g and private lambda/mu dictionaries. Public key encrypts/sums; private decrypts.
    """
    if bits < 128:
        raise ValueError("Use at least 128 modulus bits.")
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        lam = math.lcm(p - 1, q - 1)
        if math.gcd(lam, n) == 1:
            return {"n": n, "g": n + 1}, {"lambda": lam, "mu": pow(lam, -1, n)}


def random_unit(n):
    """Input: modulus. Choose a random value in 1..n-1 that has a modular inverse.
    Output: coprime random integer. Used as Paillier randomness and proof randomness.
    """
    while True:
        value = secrets.randbelow(n - 1) + 1
        if math.gcd(value, n) == 1:
            return value


def paillier_encrypt(public, value, return_randomness=False):
    """Input: public key and integer in 0..n-1; optionally request the random witness.
    Output: ciphertext, or (ciphertext,r) for ballot proofs. Never publish an individual vote's r.
    """
    n = public["n"]
    if not isinstance(value, int) or not 0 <= value < n:
        raise ValueError("Paillier input outside 0..n-1.")
    r = random_unit(n)
    ciphertext = pow(public["g"], value, n * n) * pow(r, n, n * n) % (n * n)
    return (ciphertext, r) if return_randomness else ciphertext


def check_ciphertext(public, ciphertext):
    """Input: Paillier public key and untrusted ciphertext integer. Validate its group/range.
    Output: nothing; raise ValueError if it is not an invertible element modulo n squared.
    """
    n = public["n"]
    if (
        not isinstance(ciphertext, int)
        or not 0 < ciphertext < n * n
        or math.gcd(ciphertext, n) != 1
    ):
        raise ValueError("Invalid Paillier ciphertext.")


def encrypted_sum(public, ciphertexts):
    """Input: public Paillier key and ciphertext list. Multiply valid ciphertexts modulo n squared.
    Output: encrypted sum modulo n. This function has no private-key parameter and cannot decrypt inputs.
    """
    result = 1
    n2 = public["n"] ** 2
    for value in ciphertexts:
        check_ciphertext(public, value)
        result = result * value % n2
    return result


def paillier_decrypt(public, private, ciphertext):
    """Input: matching keys and aggregate ciphertext. Apply Paillier's L function and private inverse.
    Output: plaintext integer modulo n. Application roles decide which aggregates may be decrypted.
    """
    check_ciphertext(public, ciphertext)
    n = public["n"]
    value = pow(ciphertext, private["lambda"], n * n)
    return ((value - 1) // n) * private["mu"] % n


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


def initialize_portal(folder):
    """Input: portal storage directory. Generate persistent AES-192, RSA, HMAC and Paillier keys once.
    Output: key dictionary and grant registry. Existing records and keys survive program restarts.
    """
    folder.mkdir(parents=True, exist_ok=True)
    keys = read_json(folder / "keys.json")
    if keys is None:
        public, private = paillier_keys(512)
        keys = {
            "aes": get_random_bytes(24).hex(),
            "rsa": rsa_pair(2048),
            "index": get_random_bytes(32).hex(),
            "paillier_public": public,
            "paillier_private": private,
        }
        save_json(folder / "keys.json", keys, True)
    return keys, read_json(folder / "grants.json", {"records": {}, "index": {}})


def grant_payload(record):
    """Input: stored grant including digest/signature. Select the encrypted fields that must be authenticated.
    Output: record dictionary excluding digest and signature, preventing recursive signing.
    """
    return {name: value for name, value in record.items() if name not in ("md5", "signature")}


def verify_grant(record, keys):
    """Input: stored encrypted grant and trusted RSA public key. Recompute MD5 and verify its RSA signature.
    Output: True only when both checks pass; no description or amount decryption is needed.
    """
    try:
        data = canonical(grant_payload(record))
        return hmac.compare_digest(hashlib.md5(data).hexdigest(), record["md5"]) and rsa_verify(
            keys["rsa"]["public"], data, record["signature"], "md5"
        )
    except (ValueError, KeyError, TypeError):
        return False


def submit_grant(registry, keys, role, grant_id, description, amount_paise, researcher):
    """Input: registry, keys, authenticated researcher role, grant fields and integer paise.
    Output: signed encrypted grant inserted in place. Reject duplicate IDs and out-of-range amounts.
    """
    require_role(role, ("researcher",))
    if not grant_id.strip() or not description.strip():
        raise ValueError("Grant ID/description required.")
    if not isinstance(amount_paise, int) or not 0 <= amount_paise <= 10**12:
        raise ValueError("Amount must be 0..10000000000.00.")
    lookup = token(bytes.fromhex(keys["index"]), grant_id.strip())
    if lookup in registry["index"]:
        raise ValueError("Grant ID already exists.")
    locator = secrets.token_hex(12)
    record = {
        "grant_id": grant_id.strip(),
        "description": seal(description.encode(), bytes.fromhex(keys["aes"])),
        "amount": paillier_encrypt(keys["paillier_public"], amount_paise),
        "researcher": researcher,
        "created": time.time(),
    }
    payload = canonical(record)
    record["md5"] = hashlib.md5(payload).hexdigest()
    record["signature"] = rsa_sign(keys["rsa"]["private"], payload, "md5")
    registry["records"][locator] = record
    registry["index"][lookup] = locator
    return record


def find_grant(registry, keys, role, grant_id):
    """Input: registry, lookup key, allowed role and exact grant ID. Select one indexed record.
    Output: stored grant after identity/signature checks; ciphertext contents remain encrypted.
    """
    require_role(role, ("researcher", "reviewer", "finance"))
    lookup = token(bytes.fromhex(keys["index"]), grant_id.strip())
    locator = registry["index"].get(lookup)
    if locator not in registry["records"]:
        raise ValueError("Grant ID not found.")
    record = registry["records"][locator]
    if record["grant_id"] != grant_id.strip() or not verify_grant(record, keys):
        raise ValueError("Grant integrity/signature verification failed.")
    return record


def review_description(registry, keys, role, grant_id):
    """Input: authenticated reviewer role and grant ID. Verify then AES-decrypt only its description.
    Output: plaintext description bytes; display as a hexadecimal dump in the reviewer menu.
    """
    require_role(role, ("reviewer",))
    record = find_grant(registry, keys, role, grant_id)
    return open_seal(record["description"], bytes.fromhex(keys["aes"]))


def aggregate_grants(registry, keys, role, grant_ids):
    """Input: finance role and distinct selected grant IDs. Aggregate only encrypted amounts, verify and decrypt total.
    Output: encrypted total and final integer paise. Reject all selected data if any signature is invalid.
    """
    require_role(role, ("finance",))
    if not grant_ids or len(set(grant_ids)) != len(grant_ids):
        raise ValueError("Select a nonempty list of unique grant IDs.")
    if len(grant_ids) * 10**12 >= keys["paillier_public"]["n"]:
        raise ValueError("Potential total exceeds Paillier modulus.")
    selected = []
    for grant_id in grant_ids:
        lookup = token(bytes.fromhex(keys["index"]), grant_id.strip())
        locator = registry["index"].get(lookup)
        if locator not in registry["records"]:
            raise ValueError("Grant not found: " + grant_id)
        record = registry["records"][locator]
        if record["grant_id"] != grant_id.strip():
            raise ValueError("Index identity mismatch.")
        selected.append(record)
    aggregate = encrypted_sum(keys["paillier_public"], [record["amount"] for record in selected])
    if not all(verify_grant(record, keys) for record in selected):
        raise ValueError("Tampered selected grant; total will NOT be decrypted.")
    return aggregate, paillier_decrypt(keys["paillier_public"], keys["paillier_private"], aggregate)


def role_menu(folder, keys, registry, username, role):
    """Input: authenticated role/session and persisted portal state. Expose only allowed operations.
    Output: saved submissions, verification/search results or aggregate totals; return on logout.
    """
    while True:
        print("\nLogged in as", username, "role:", role)
        if role == "researcher":
            print("1 Submit  2 View all encrypted submissions  0 Logout")
        elif role == "reviewer":
            print("1 Verify/find Grant ID  2 Description hexadecimal dump  3 Verify all  0 Logout")
        else:
            print("1 Aggregate selected grants  2 View encrypted grants  0 Logout")
        try:
            choice = ask_text("Role choice")
            if choice == "0":
                return
            if role == "researcher" and choice == "1":
                record = submit_grant(
                    registry,
                    keys,
                    role,
                    ask_text("Grant ID"),
                    ask_text("Description"),
                    parse_amount(ask_text("Amount")),
                    username,
                )
                save_json(folder / "grants.json", registry)
                audit(
                    folder,
                    "grant_submitted",
                    {"id": record["grant_id"], "by": username},
                    keys["rsa"]["private"],
                )
                print("Stored encrypted grant:", json.dumps(record, indent=2))
            elif (role == "researcher" and choice == "2") or (role == "finance" and choice == "2"):
                print(json.dumps(registry["records"], indent=2))
            elif role == "reviewer" and choice == "1":
                record = find_grant(registry, keys, role, ask_text("Grant ID"))
                print(
                    "MD5 and RSA verified:",
                    verify_grant(record, keys),
                    "Encrypted record:",
                    json.dumps(record, indent=2),
                )
            elif role == "reviewer" and choice == "2":
                data = review_description(registry, keys, role, ask_text("Grant ID"))
                print("Description hexadecimal dump:", data.hex(" "))
            elif role == "reviewer" and choice == "3":
                for record in registry["records"].values():
                    print(record.get("grant_id"), verify_grant(record, keys))
            elif role == "finance" and choice == "1":
                ids = [
                    value.strip()
                    for value in ask_text("Selected Grant IDs, comma separated").split(",")
                ]
                encrypted, total = aggregate_grants(registry, keys, role, ids)
                print(
                    "Encrypted aggregate:", encrypted, "Final expense total:", format_amount(total)
                )
                audit(
                    folder,
                    "aggregate_decrypted",
                    {"ids": ids, "by": username},
                    keys["rsa"]["private"],
                )
            else:
                print("Option is not permitted for this role.")
        except (
            ValueError,
            KeyError,
            TypeError,
            PermissionError,
            OSError,
            InvalidOperation,
        ) as error:
            print("Rejected:", error)
            audit(
                folder,
                "operation_rejected",
                {"role": role, "reason": str(error)},
                keys["rsa"]["private"],
            )


def main():
    """Input: first-run role passwords, then login/menu choices. Start the persistent grant portal.
    Output: role-based menu, encrypted JSON records and signed audit trail. Run python solution.py.
    """
    folder = Path(__file__).resolve().parent / "storage"
    keys, registry = initialize_portal(folder)
    accounts = setup_accounts(folder / "accounts.json", ("researcher", "reviewer", "finance"))
    while True:
        print("\n1 Login  2 Verify audit trail  0 Exit")
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice == "1":
                username, role = login(accounts)
                role_menu(folder, keys, registry, username, role)
            elif choice == "2":
                print("Audit verified:", verify_audit(folder, keys["rsa"]["public"]))
            else:
                print("Choose a listed option.")
        except (ValueError, PermissionError, OSError) as error:
            print("Rejected:", error)
            audit(folder, "login_rejected", {"reason": str(error)}, keys["rsa"]["private"])


if __name__ == "__main__":
    main()
