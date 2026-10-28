"""Exam workflow: AES-256-GCM, RSA-OAEP, SHA-256, ElGamal signature.
Every saved artifact is a separate .txt file. Run normally and use Menu().
"""

import hmac
import json
import math
import os
import secrets
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Random import get_random_bytes

BASE = Path(__file__).resolve().parent
STORE = BASE / "practice_data"
KEYS = STORE / "keys"
OUTBOX = STORE / "outbox"


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
    Use Write_Text(KEYS / 'sender/private_key.txt', json_text, True).
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


def Key_Setup():
    """Input: none. Generate/save both identities only if no identity files exist.
    Output: None. Existing complete pairs are checked and reused; missing/mismatched keys are refused.
    Never regenerate receiver private key after a message was encrypted to its public key.
    """
    paths = [
        KEYS / "sender/private_key.txt",
        KEYS / "sender/public_key.txt",
        KEYS / "receiver/private_key.txt",
        KEYS / "receiver/public_key.txt",
    ]
    present = [p.exists() for p in paths]
    if any(present):
        if not all(present):
            raise ValueError(
                "Incomplete key setup: restore missing keys; do not replace identities"
            )
        sender_private = json.loads(Read_Text(paths[0]))
        sender_public = json.loads(Read_Text(paths[1]))
        expected = {
            "p": sender_private["p"],
            "g": sender_private["g"],
            "y": pow(sender_private["g"], sender_private["x"], sender_private["p"]),
        }
        receiver = RSA.import_key(Read_Text(paths[2]))
        if (
            sender_public != expected
            or receiver.public_key().export_key()
            != RSA.import_key(Read_Text(paths[3])).public_key().export_key()
        ):
            raise ValueError("Public/private key mismatch")
        print("Existing identity keys checked and reused")
        return
    receiver_private, receiver_public = Generate_Receiver_Keys()
    sender_private, sender_public = Generate_Sender_Keys()
    Write_Text(paths[0], json.dumps(sender_private, indent=2), True)
    Write_Text(paths[1], json.dumps(sender_public, indent=2))
    Write_Text(paths[2], receiver_private, True)
    Write_Text(paths[3], receiver_public)
    print("Created RSA-2048 receiver and 256-bit practice ElGamal sender keys")


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


def Metadata(record_id, sender_public, receiver_public):
    """Input: record ID and public keys. Build algorithm labels and public-key fingerprints.
    Output: dict; signed as package data and authenticated as AES-GCM AAD.
    """
    if not record_id.strip():
        raise ValueError("Record ID cannot be empty")
    return {
        "record_id": record_id,
        "version": 1,
        "cipher": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature": "ElGamal-SHA256",
        "hash": "SHA256",
        "sender_fingerprint": Hash_Generate(Canonical(sender_public)),
        "receiver_fingerprint": Hash_Generate(
            RSA.import_key(receiver_public).public_key().export_key(format="DER")
        ),
    }


def Write_Cipher(envelope):
    """Input: ciphertext/nonce/tag hex dict. Save ciphertext.txt, nonce.txt, tag.txt separately.
    Output: None. All three are necessary; never throw away nonce or authentication tag.
    """
    for name in ("ciphertext", "nonce", "tag"):
        Write_Text(OUTBOX / (name + ".txt"), envelope[name])


def Write_Key(encrypted_key):
    """Input: RSA-wrapped AES key hex str. Save encrypted_key.txt. Output: None; not the plaintext key."""
    Write_Text(OUTBOX / "encrypted_key.txt", encrypted_key)


def Write_DS(signature):
    """Input: signature {r,s}. Save its integer components as JSON text in signature.txt. Output: None."""
    Write_Text(OUTBOX / "signature.txt", json.dumps(signature, indent=2))


def Write_Hash(digest):
    """Input: SHA-256 hex str. Save hash.txt separately. Output: None."""
    Write_Text(OUTBOX / "hash.txt", digest)


def Read_Package():
    """Input: none. Read public artifacts from outbox .txt files, preserving their field meanings.
    Output: package dict, signature dict, digest str. Does not read any private/symmetric key.
    """
    package = {
        name: Read_Text(OUTBOX / (name + ".txt")).strip()
        for name in ("ciphertext", "nonce", "tag", "encrypted_key")
    }
    package["metadata"] = json.loads(Read_Text(OUTBOX / "metadata.txt"))
    package["sender_public"] = json.loads(Read_Text(OUTBOX / "sender_public_key.txt"))
    package["receiver_public"] = Read_Text(OUTBOX / "receiver_public_key.txt")
    return (
        package,
        json.loads(Read_Text(OUTBOX / "signature.txt")),
        Read_Text(OUTBOX / "hash.txt").strip(),
    )


def Send(plaintext, record_id):
    """Input: plaintext str and record ID. Use existing keys, fresh AES key, encrypt, hash/sign, save.
    Output: package dict. Saves sender's AES key separately in private storage as explicitly requested.
    The receiver never reads that saved plaintext AES key; it must unwrap encrypted_key.txt.
    """
    sender_private = json.loads(Read_Text(KEYS / "sender/private_key.txt"))
    sender_public = json.loads(Read_Text(KEYS / "sender/public_key.txt"))
    receiver_public = Read_Text(KEYS / "receiver/public_key.txt")
    metadata = Metadata(record_id, sender_public, receiver_public)
    key = Generate_Symmetric_Key()
    envelope = Encrypt(plaintext.encode("utf-8"), key, Canonical(metadata))
    package = {
        **envelope,
        "encrypted_key": Encrypt_Key(key, receiver_public),
        "metadata": metadata,
        "sender_public": sender_public,
        "receiver_public": receiver_public,
    }
    data = Canonical(package)
    signature = DS_Sign(data, sender_private)
    digest = Hash_Generate(data)
    Write_Text(KEYS / "sender/symmetric_key.txt", key.hex(), True)
    Write_Cipher(envelope)
    Write_Key(package["encrypted_key"])
    Write_Text(OUTBOX / "metadata.txt", json.dumps(metadata, indent=2))
    Write_Text(OUTBOX / "sender_public_key.txt", json.dumps(sender_public, indent=2))
    Write_Text(OUTBOX / "receiver_public_key.txt", receiver_public)
    Write_DS(signature)
    Write_Hash(digest)
    return package


def Verify_Package(package, signature, digest):
    """Input: received package/signature/digest. Compare received keys to independently trusted locals,
    validate metadata, check SHA-256 and ElGamal signature. Output: dict of boolean checks plus overall.
    Verification uses only public files and ciphertext; never either private key or saved AES key.
    """
    trusted_sender = json.loads(Read_Text(KEYS / "sender/public_key.txt"))
    trusted_receiver = Read_Text(KEYS / "receiver/public_key.txt")
    sender_ok = package["sender_public"] == trusted_sender
    receiver_ok = (
        RSA.import_key(package["receiver_public"]).public_key().export_key()
        == RSA.import_key(trusted_receiver).public_key().export_key()
    )
    metadata_ok = package["metadata"] == Metadata(
        package["metadata"]["record_id"], trusted_sender, trusted_receiver
    )
    data = Canonical(package)
    checks = {
        "sender_key": sender_ok,
        "receiver_key": receiver_ok,
        "metadata": metadata_ok,
        "signature": DS_Verify(data, signature, trusted_sender),
        "hash": Hash_Check(data, digest),
    }
    checks["overall"] = all(checks.values())
    return checks


def Receive():
    """Input: none. Read artifacts, verify before unwrapping AES key, then GCM-authenticate/decrypt.
    Output: plaintext str. Raises on any failed check; never decrypts a package with overall=False.
    No plaintext or recovered AES key is written by the receiver.
    """
    package, signature, digest = Read_Package()
    checks = Verify_Package(package, signature, digest)
    print("Verification:", checks)
    if not checks["overall"]:
        raise ValueError("Verification failed; refusing key and message decryption")
    private = Read_Text(KEYS / "receiver/private_key.txt")
    key = Decrypt_Key(package["encrypted_key"], private)
    plaintext = Decrypt(package, key, Canonical(package["metadata"]))
    return plaintext.decode("utf-8")


def Menu():
    """Input: menu choices, record ID and plaintext. Coordinate setup/send/public checks/receive.
    Output: printed results. Choose setup once; sending overwrites the current outbox and AES key.
    This is a local workflow with no authenticated user roles, networking or command-line flags.
    """
    while True:
        print(
            "\n1 Generate/load identity keys\n2 Sender: input, encrypt, sign, hash and save\n3 Verify stored package (public keys only)\n4 Receiver: verify, unwrap key and decrypt\n0 Exit"
        )
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                return
            if choice == "1":
                Key_Setup()
            elif choice == "2":
                record_id = input("Record ID: ").strip()
                text = input("Plaintext: ")
                Send(text, record_id)
                print("Saved separate .txt artifacts in", OUTBOX)
            elif choice == "3":
                print("Verification:", Verify_Package(*Read_Package()))
            elif choice == "4":
                print("Recovered plaintext:", Receive())
            else:
                print("Choose a displayed option")
        except (ValueError, TypeError, KeyError, OSError, EOFError) as error:
            print("Operation failed:", error)


if __name__ == "__main__":
    Menu()
