# Lab 4 Q2: Rabin hospital key-management service
# Educational lab exercise. No user-defined classes are used.

import json
import time
import secrets
import hashlib
from pathlib import Path


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


def ask_int(label, default, minimum=None, maximum=None):
    """Input: prompt, default integer, optional inclusive limits. Read and validate a number.
    Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.
    """
    value = int(ask_text(label, default))
    if minimum is not None and value < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be at most {maximum}.")
    return value


from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime


def seal(data, key):
    """Input: plaintext bytes and AES key. Encrypt and authenticate using AES-GCM.
    Output: dictionary containing nonce, tag and ciphertext as hex strings for JSON storage.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {"nonce": cipher.nonce.hex(), "tag": tag.hex(), "ciphertext": ciphertext.hex()}


def open_seal(record, key):
    """Input: GCM record and matching AES key. Verify the tag while decrypting.
    Output: plaintext bytes. Wrong keys or modified data raise ValueError.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(record["nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(record["ciphertext"]), bytes.fromhex(record["tag"])
    )


def rabin_keys(bits=1024):
    """Input: desired modulus size. Generate distinct primes congruent to 3 modulo 4.
    Output: public modulus n and private pair (p,q). Used by Rabin encryption/decryption.
    """
    if bits < 256:
        raise ValueError("Use at least 256 bits for this demonstration.")
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits - bits // 2)
        if p != q and p % 4 == 3 and q % 4 == 3:
            return p * q, (p, q)


def rabin_encrypt(n, message):
    """Input: public modulus and integer in 0..n-1. Square the message modulo n.
    Output: ciphertext integer. Different messages can have the same square.
    """
    if not 0 <= message < n:
        raise ValueError("Message outside Rabin range.")
    return pow(message, 2, n)


def rabin_roots(private, ciphertext):
    """Input: (p,q) and Rabin ciphertext. Compute square roots and combine with CRT.
    Output: list of up to four integer roots. Extra message redundancy chooses the original.
    """
    p, q = private
    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    first = (mp * q * pow(q, -1, p) + mq * p * pow(p, -1, q)) % n
    second = (mp * q * pow(q, -1, p) - mq * p * pow(p, -1, q)) % n
    return sorted({first, (-first) % n, second, (-second) % n})


def rabin_wrap_key(n, key):
    """Input: Rabin modulus and 16-byte AES key. Add marker and checksum to disambiguate roots.
    Output: ciphertext integer. This illustrative encoding is not a standardized padding scheme.
    """
    if len(key) != 16:
        raise ValueError("Use a 16-byte AES key.")
    encoded = b"RB" + key + hashlib.sha256(key).digest()[:8]
    message = int.from_bytes(encoded, "big")
    if message >= n:
        raise ValueError("Modulus too small for the encoded key.")
    return rabin_encrypt(n, message)


def rabin_unwrap_key(private, ciphertext):
    """Input: Rabin private primes and wrapped key integer. Test roots for marker/checksum.
    Output: exactly one 16-byte AES key, or ValueError when the ciphertext is invalid.
    """
    candidates = []
    for root in rabin_roots(private, ciphertext):
        if root.bit_length() > 26 * 8:
            continue
        data = root.to_bytes(26, "big")
        key = data[2:18]
        if data[:2] == b"RB" and data[18:] == hashlib.sha256(key).digest()[:8]:
            candidates.append(key)
    if len(candidates) != 1:
        raise ValueError("Could not identify one valid Rabin root.")
    return candidates[0]


import hmac


def load_store(folder):
    """Input: storage directory. Load registry plus local AES master key, or initialize them.
    Output: (registry, master key). Secret material is kept in owner-only files.
    """
    folder.mkdir(parents=True, exist_ok=True)
    master_path = folder / "master.key"
    if not master_path.exists():
        master_path.write_bytes(get_random_bytes(32))
        master_path.chmod(0o600)
    registry_path = folder / "registry.json"
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    return registry, master_path.read_bytes()


def save_store(folder, registry, event):
    """Input: directory, registry and event text. Save registry and append timestamped audit log.
    Output: registry.json and audit.jsonl files. Called after every key/access mutation.
    """
    path = folder / "registry.json"
    path.write_text(json.dumps(registry, indent=2))
    path.chmod(0o600)
    with (folder / "audit.jsonl").open("a") as stream:
        stream.write(json.dumps({"time": time.time(), "event": event}) + "\n")


def issue_facility(registry, name, bits, master, lifetime=365 * 24 * 3600):
    """Input: registry, new facility name, bit size, master key and lifetime seconds.
    Output: one-time access token; store public key, encrypted private primes and token hash.
    """
    if not name or name in registry:
        raise ValueError("Use a new facility name.")
    n, private = rabin_keys(bits)
    token = secrets.token_hex(16)
    registry[name] = {
        "n": n,
        "private": seal(json.dumps(list(private)).encode(), master),
        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "created": time.time(),
        "expires": time.time() + lifetime,
        "active": True,
        "bits": bits,
    }
    return token


def request_keys(registry, name, token, master, now=None):
    """Input: facility name, access token, registry and master key. Check identity/status/expiry.
    Output: authorized (n,(p,q)) pair. This function is the local key-distribution API.
    """
    record = registry[name]
    now = time.time() if now is None else now
    if not record["active"] or now >= record["expires"]:
        raise ValueError("Facility key is revoked or expired.")
    received = hashlib.sha256(token.encode()).hexdigest()
    if not hmac.compare_digest(received, record["token_hash"]):
        raise ValueError("Invalid facility token.")
    private = tuple(json.loads(open_seal(record["private"], master)))
    return record["n"], private


def renew_due(registry, master, now=None):
    """Input: registry, master key and optional time. Renew expired active facility keys.
    Output: list of renewed names. Retain facility tokens; replace public/private key material.
    """
    now = time.time() if now is None else now
    renewed = []
    for name, record in registry.items():
        if record["active"] and now >= record["expires"]:
            n, private = rabin_keys(record["bits"])
            record.update(
                {
                    "n": n,
                    "private": seal(json.dumps(list(private)).encode(), master),
                    "created": now,
                    "expires": now + 365 * 24 * 3600,
                }
            )
            renewed.append(name)
    return renewed


def exercise():
    """Input: facility/key-management menu choices. Manage Rabin keys and patient encryption.
    Output: persisted encrypted keys, patient envelopes, authorized recovery and audit log.
    """
    folder = Path(__file__).resolve().parent / "storage"
    registry, master = load_store(folder)
    renewed = renew_due(registry, master)
    if renewed:
        save_store(folder, registry, "automatically renewed " + str(renewed))
    while True:
        print("\n1 Add facility  2 List public keys  3 Request keys/decrypt patient demo")
        print("4 Revoke  5 Renew expired keys  6 Compare Rabin/RSA  0 Back")
        choice = input("Operation: ").strip()
        if choice == "0":
            return
        try:
            if choice == "1":
                name = ask_text("Facility", "Hospital_A")
                bits = ask_int("Modulus bits", 1024, 256, 4096)
                token = issue_facility(registry, name, bits, master)
                save_store(folder, registry, "issued " + name)
                print("Save this facility access token:", token)
            elif choice == "2":
                for name, record in registry.items():
                    print(
                        name,
                        "public n:",
                        record["n"],
                        "active:",
                        record["active"],
                        "expiry:",
                        record["expires"],
                    )
            elif choice == "3":
                name = ask_text("Facility", "Hospital_A")
                token = ask_text("Facility token", "enter-issued-token")
                n, private = request_keys(registry, name, token, master)
                text = ask_text("Patient record", "Patient 101: follow-up required")
                session = get_random_bytes(16)
                encrypted = seal(text.encode(), session)
                wrapped = rabin_wrap_key(n, session)
                recovered = open_seal(encrypted, rabin_unwrap_key(private, wrapped))
                print(
                    "Wrapped AES key:",
                    wrapped,
                    "Encrypted patient:",
                    encrypted,
                    "Recovered:",
                    recovered.decode(),
                )
                save_store(folder, registry, "authorized key request " + name)
            elif choice == "4":
                name = ask_text("Facility", "Hospital_A")
                registry[name]["active"] = False
                save_store(folder, registry, "revoked " + name)
            elif choice == "5":
                names = renew_due(registry, master)
                save_store(folder, registry, "renewal check " + str(names))
                print("Renewed:", names)
            elif choice == "6":
                start = time.perf_counter()
                n, private = rabin_keys(1024)
                rabin_time = time.perf_counter() - start
                start = time.perf_counter()
                rsa = RSA.generate(2048)
                rsa_time = time.perf_counter() - start
                message = 42
                c = rabin_encrypt(n, message)
                print("Rabin-1024 keygen s:", rabin_time, "RSA-2048 keygen s:", rsa_time)
                print(
                    "Rabin four roots:",
                    rabin_roots(private, c),
                    "original included:",
                    message in rabin_roots(private, c),
                )
                print(
                    "Rabin needs root disambiguation; RSA-OAEP has standardized message encoding. These sizes are not equal-security claims."
                )
            else:
                print("Invalid choice.")
        except (ValueError, KeyError, OSError) as error:
            print("Rejected:", error)
            save_store(folder, registry, "rejected operation " + choice)


def main():
    """Input: terminal choices. Run the exercise safely.
    Output: printed results. Use python solution.py and choose a menu option.
    """
    while True:
        print("\n1. Run exercise (you can change the inputs)\n0. Exit")
        choice = input("Choice: ").strip()
        if choice == "0":
            return
        if choice != "1":
            print("Choose 1 or 0.")
            continue
        try:
            exercise()
        except (ValueError, TypeError, KeyError, OSError) as error:
            print("Could not complete operation:", error)


if __name__ == "__main__":
    main()
