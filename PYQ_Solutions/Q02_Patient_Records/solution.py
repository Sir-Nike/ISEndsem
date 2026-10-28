import json
import math
import secrets
import hashlib
import hmac
from pathlib import Path
from decimal import InvalidOperation
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA512, MD5
from Crypto.Signature import pkcs1_15
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


def ask_int(label, default=None, minimum=None, maximum=None):
    """Input: prompt, optional default and inclusive bounds. Read and validate an integer.
    Output: integer, or ValueError. Use for menu parameters, counts and cryptographic sizes.
    """
    value = int(ask_text(label, default))
    if minimum is not None and value < minimum:
        raise ValueError(label + " is too small.")
    if maximum is not None and value > maximum:
        raise ValueError(label + " is too large.")
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


def initialize_keys(folder, aes_bytes=32):
    """Input: storage folder and AES length 16/24/32. Create keys once, then reuse saved keys.
    Output: dictionary of AES/HMAC/RSA/Paillier keys. Reloading preserves old ciphertext readability.
    """
    path = folder / "keys.json"
    existing = read_json(path)
    if existing is not None:
        return existing
    if aes_bytes not in (16, 24, 32):
        raise ValueError("AES key length must be 16,24 or 32 bytes.")
    public, private = paillier_keys(512)
    keys = {
        "aes": get_random_bytes(aes_bytes).hex(),
        "index": get_random_bytes(32).hex(),
        "rsa": rsa_pair(2048),
        "paillier_public": public,
        "paillier_private": private,
    }
    save_json(path, keys, True)
    return keys


def validate_patient(record):
    """Input: one patient dictionary. Require five fields, nonempty text and nonnegative integer glucose.
    Output: normalized patient record. Use before saving or encrypting user-entered exam data.
    """
    fields = ("Patient_id", "Patient_name", "Diagnosis", "Treatment")
    result = {field: str(record[field]).strip() for field in fields}
    if any(not value for value in result.values()):
        raise ValueError("Patient text fields cannot be empty.")
    glucose = record["Blood_glucose"]
    if isinstance(glucose, bool) or not isinstance(glucose, int) or not 0 <= glucose <= 1000000:
        raise ValueError("Blood_glucose must be an integer in 0..1000000.")
    result["Blood_glucose"] = glucose
    return result


def enter_dataset(folder):
    """Input: user-entered patient count and five fields per patient. Validate uniqueness and values.
    Output: Patient_records.json saved; returns the new list. Overwriting requires explicit confirmation.
    """
    path = folder / "Patient_records.json"
    if path.exists() and ask_text("Replace current dataset? type YES", "no") != "YES":
        return read_json(path)
    count = ask_int("Patient count (enter the provided dataset)", 3, 1, 1000)
    examples = [
        ("P001", "Alice", "Diabetes", 140, "Diet review"),
        ("P002", "Bob", "Hypertension", 95, "Follow up"),
        ("P003", "Carol", "Diabetes", 160, "Medication review"),
    ]
    records = []
    seen = set()
    print(
        "Displayed defaults are illustrative only. Replace them with the dataset supplied in your exam."
    )
    for index in range(count):
        pid, name, diagnosis, glucose, treatment = examples[index % len(examples)]
        record = {
            "Patient_id": ask_text("Patient ID", pid if index < 3 else f"P{index+1:03d}"),
            "Patient_name": ask_text("Name", name),
            "Diagnosis": ask_text("Diagnosis", diagnosis),
            "Blood_glucose": ask_int("Blood glucose", glucose, 0, 1000000),
            "Treatment": ask_text("Treatment", treatment),
        }
        record = validate_patient(record)
        if record["Patient_id"] in seen:
            raise ValueError("Duplicate patient ID.")
        seen.add(record["Patient_id"])
        records.append(record)
    save_json(path, records, True)
    print("Saved", len(records), "patients. Re-encrypt and sign after changing the source data.")
    return records


def encrypt_dataset(folder, keys):
    """Input: folder and saved keys. AES-GCM-encrypt each complete record; Paillier-encrypt glucose separately.
    Output: encrypted_patient_records.json, including diagnosis HMAC index; no original record fields inside ciphertext metadata.
    """
    records = read_json(folder / "Patient_records.json")
    if records is None:
        raise ValueError("Enter the patient dataset first (option 10).")
    encrypted = {
        "version": 1,
        "aes_bytes": len(bytes.fromhex(keys["aes"])),
        "records": {},
        "diagnosis_index": {},
    }
    for source in records:
        record = validate_patient(source)
        pid = record["Patient_id"]
        if pid in encrypted["records"]:
            raise ValueError("Duplicate patient ID.")
        envelope = seal(canonical(record), bytes.fromhex(keys["aes"]))
        encrypted["records"][pid] = {
            "record": envelope,
            "glucose": paillier_encrypt(keys["paillier_public"], record["Blood_glucose"]),
        }
        diagnosis_token = token(
            bytes.fromhex(keys["index"]), record["Diagnosis"].strip().casefold()
        )
        encrypted["diagnosis_index"].setdefault(diagnosis_token, []).append(pid)
    save_json(folder / "encrypted_patient_records.json", encrypted)
    print("Encrypted dataset saved:", len(encrypted["records"]), "records. Sign it using option 4.")
    return encrypted


def sign_dataset(folder, keys):
    """Input: data folder and RSA identity. Sign current plaintext source and encrypted snapshot separately.
    Output: dataset_signature.json and printed signatures. Binding both catches edits to either file.
    """
    source = read_json(folder / "Patient_records.json")
    encrypted = read_json(folder / "encrypted_patient_records.json")
    if source is None or encrypted is None:
        raise ValueError("Enter and encrypt the dataset before signing.")
    # Confirm that this encrypted snapshot actually corresponds to this source before certifying it.
    recovered = [
        json.loads(open_seal(item["record"], bytes.fromhex(keys["aes"])))
        for item in encrypted["records"].values()
    ]
    source_by_id = {row["Patient_id"]: validate_patient(row) for row in source}
    recovered_by_id = {row["Patient_id"]: row for row in recovered}
    if len(source_by_id) != len(source) or source_by_id != recovered_by_id:
        raise ValueError("Source changed since encryption. Encrypt again before signing.")
    for pid, item in encrypted["records"].items():
        if (
            paillier_decrypt(keys["paillier_public"], keys["paillier_private"], item["glucose"])
            != source_by_id[pid]["Blood_glucose"]
        ):
            raise ValueError("Encrypted glucose does not match the source. Encrypt again.")
    signature = {
        "source": rsa_sign(keys["rsa"]["private"], canonical(source)),
        "encrypted": rsa_sign(keys["rsa"]["private"], canonical(encrypted)),
    }
    save_json(folder / "dataset_signature.json", signature)
    print("Plain dataset RSA signature:", signature["source"])
    print("Encrypted dataset RSA signature:", signature["encrypted"])
    return signature


def verify_dataset(folder, keys):
    """Input: folder and trusted RSA public identity. Verify both current source and encrypted snapshot.
    Output: boolean; invalid/missing/malformed signatures or changed file contents return False.
    """
    try:
        signatures = read_json(folder / "dataset_signature.json")
        source = read_json(folder / "Patient_records.json")
        encrypted = read_json(folder / "encrypted_patient_records.json")
        return bool(
            signatures
            and source is not None
            and encrypted is not None
            and rsa_verify(keys["rsa"]["public"], canonical(source), signatures["source"])
            and rsa_verify(keys["rsa"]["public"], canonical(encrypted), signatures["encrypted"])
        )
    except (ValueError, KeyError, TypeError):
        return False


def require_verified_dataset(folder, keys):
    """Input: dataset folder and keys. Reject access if current source/encrypted signatures are invalid.
    Output: verified encrypted snapshot. Call before search, sums or selected-record decryption.
    """
    if not verify_dataset(folder, keys):
        raise ValueError("Verification FAILED. Dataset is unsigned, changed or damaged.")
    return read_json(folder / "encrypted_patient_records.json")


def record_hash(folder, patient_id):
    """Input: source file folder and patient ID. Locate exactly one source record and hash its canonical form.
    Output: SHA-256 hexadecimal digest. Hashing is not encryption and cannot be reversed.
    """
    source = read_json(folder / "Patient_records.json", [])
    matches = [record for record in source if record["Patient_id"] == patient_id]
    if len(matches) != 1:
        raise ValueError("Patient ID not found or duplicated.")
    return hashlib.sha256(canonical(matches[0])).hexdigest()


def total_glucose(folder, keys):
    """Input: verified encrypted dataset and Paillier keys. Sum ciphertexts without decrypting patients.
    Output: (aggregate ciphertext, final plaintext sum). Only the aggregate is decrypted in this operation.
    """
    encrypted = require_verified_dataset(folder, keys)
    count = len(encrypted["records"])
    if count * 1000000 >= keys["paillier_public"]["n"]:
        raise ValueError("Potential total exceeds the modulus.")
    aggregate = encrypted_sum(
        keys["paillier_public"], [row["glucose"] for row in encrypted["records"].values()]
    )
    return aggregate, paillier_decrypt(keys["paillier_public"], keys["paillier_private"], aggregate)


def search_diagnosis(folder, keys, diagnosis):
    """Input: folder, keys and diagnosis text. Compute one normalized HMAC token and look up matching IDs.
    Output: patient ID list. Does not decrypt patient records or scan their plaintext diagnoses.
    """
    encrypted = require_verified_dataset(folder, keys)
    query = token(bytes.fromhex(keys["index"]), diagnosis.strip().casefold())
    return encrypted["diagnosis_index"].get(query, [])


def decrypt_patient(folder, keys, patient_id):
    """Input: patient ID, folder and keys. Verify signatures first, then decrypt only the requested record.
    Output: patient dictionary. A failed dataset check prevents AES decryption entirely.
    """
    encrypted = require_verified_dataset(folder, keys)
    if patient_id not in encrypted["records"]:
        raise ValueError("Patient ID not found.")
    record = json.loads(
        open_seal(encrypted["records"][patient_id]["record"], bytes.fromhex(keys["aes"]))
    )
    if record["Patient_id"] != patient_id:
        raise ValueError("Record identity mismatch.")
    return record


def main():
    """Input: exact nine-option patient menu, plus dataset-entry and intentional-tamper helpers.
    Output: saved files, hashes, signatures, encrypted sums, matching IDs and verified selected patients.
    """
    folder = Path(__file__).resolve().parent / "storage"
    folder.mkdir(exist_ok=True)
    if not (folder / "keys.json").exists():
        aes_bytes = ask_int("AES key length in bytes: 16/24/32", 32)
        keys = initialize_keys(folder, aes_bytes)
    else:
        keys = initialize_keys(folder)
    print("First use: choose 10 to enter the supplied data, then 2 to encrypt, then 4 to sign.")
    while True:
        print("\n1 Display source dataset  2 Encrypt using AES  3 SHA-256 by patient ID")
        print("4 Sign dataset  5 Verify dataset  6 Homomorphic glucose sum  7 Search diagnosis")
        print(
            "8 Verify and decrypt patient  9 Exit  10 Enter/replace dataset  11 Simulate ciphertext tampering"
        )
        try:
            choice = ask_text("Choice")
            if choice == "9":
                return
            if choice == "1":
                print(json.dumps(read_json(folder / "Patient_records.json", []), indent=2))
            elif choice == "2":
                encrypt_dataset(folder, keys)
            elif choice == "3":
                print("SHA-256:", record_hash(folder, ask_text("Patient ID")))
            elif choice == "4":
                sign_dataset(folder, keys)
            elif choice == "5":
                print("Signature verification:", verify_dataset(folder, keys))
            elif choice == "6":
                aggregate, total = total_glucose(folder, keys)
                print("Encrypted total:", aggregate, "Decrypted final total:", total)
            elif choice == "7":
                print(
                    "Matching patient IDs:", search_diagnosis(folder, keys, ask_text("Diagnosis"))
                )
            elif choice == "8":
                print(json.dumps(decrypt_patient(folder, keys, ask_text("Patient ID")), indent=2))
            elif choice == "10":
                enter_dataset(folder)
            elif choice == "11":
                if (
                    ask_text(
                        "This intentionally damages the saved encrypted data. Type TAMPER", "cancel"
                    )
                    != "TAMPER"
                ):
                    continue
                encrypted = read_json(folder / "encrypted_patient_records.json")
                pid = ask_text("Patient ID")
                value = encrypted["records"][pid]["record"]["ciphertext"]
                encrypted["records"][pid]["record"]["ciphertext"] = (
                    "00" if value[:2] != "00" else "01"
                ) + value[2:]
                save_json(folder / "encrypted_patient_records.json", encrypted)
                print("After tampering, signature verification:", verify_dataset(folder, keys))
            else:
                print("Choose a listed option.")
        except (ValueError, KeyError, TypeError, OSError, InvalidOperation) as error:
            print("Rejected:", error)


if __name__ == "__main__":
    main()
