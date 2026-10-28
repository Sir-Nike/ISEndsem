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


def Metadata(record_id, sender, receiver, sender_public, receiver_public):
    """Input: ID, two usernames and registered public keys. Output: immutable public metadata dict.
    Its identities/algorithm labels/fingerprints are covered by the signature and GCM AAD.
    """
    return {
        "record_id": record_id,
        "sender": sender,
        "receiver": receiver,
        "version": 1,
        "cipher": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature": "ElGamal-SHA256",
        "hash": "SHA256",
        "sender_fingerprint": Public_Fingerprint(sender_public, "sender"),
        "receiver_fingerprint": Public_Fingerprint(receiver_public, "receiver"),
    }


def Create_Packet(
    text, record_id, sender, receiver, sender_private, sender_public, receiver_public
):
    """Input: plaintext str, IDs, sender private/public key and receiver public key.
    Output: (packet dict, fresh AES key bytes). Encrypt/sign/hash locally; no private key enters packet.
    """
    metadata = Metadata(record_id, sender, receiver, sender_public, receiver_public)
    key = Generate_Symmetric_Key()
    package = {
        **Encrypt(text.encode(), key, Canonical(metadata)),
        "encrypted_key": Encrypt_Key(key, receiver_public),
        "metadata": metadata,
        "sender_public": sender_public,
        "receiver_public": receiver_public,
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
        )
        checks["signature"] = DS_Verify(
            Canonical(package), packet["signature"], sender_public
        )
        checks["hash"] = Hash_Check(Canonical(package), packet["hash"])
    except (ValueError, TypeError, KeyError, OverflowError):
        pass
    checks["overall"] = all(checks.values())
    return checks


def Save_Packet(packet, folder):
    """Input: packet and destination Path. Output: None. Save each artifact separately in .txt files.
    Contains only encrypted/public data: ciphertext, nonce, tag, wrapped key, metadata, keys, DS, hash.
    """
    folder = Path(folder)
    package = packet["package"]
    for name in ("ciphertext", "nonce", "tag", "encrypted_key"):
        Write_Text(folder / (name + ".txt"), package[name])
    for name in ("metadata", "sender_public"):
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
            for name in ("metadata", "sender_public")
        }
    )
    package["receiver_public"] = Read_Text(folder / "receiver_public.txt")
    return {
        "package": package,
        "signature": json.loads(Read_Text(folder / "signature.txt")),
        "hash": Read_Text(folder / "hash.txt").strip(),
    }


def Send_JSON(connection, value):
    """Input: connected socket and JSON object. Send 4-byte network-order length then body.
    Output: None. Limit one request/reply to 4 MiB; sendall handles partial writes.
    """
    import struct

    body = Canonical(value)
    if not 0 < len(body) <= 4 * 1024 * 1024:
        raise ValueError("Packet exceeds 4 MiB limit")
    connection.sendall(struct.pack("!I", len(body)) + body)


def Read_Exact(connection, size):
    """Input: socket and expected byte count. Output: exact bytes; EOFError on truncated stream."""
    parts = bytearray()
    while len(parts) < size:
        chunk = connection.recv(size - len(parts))
        if not chunk:
            raise EOFError("Peer closed before completing message")
        parts.extend(chunk)
    return bytes(parts)


def Receive_JSON(connection):
    """Input: socket. Read bounded length-framed UTF-8 JSON. Output: dictionary or exception."""
    import struct

    size = struct.unpack("!I", Read_Exact(connection, 4))[0]
    if not 0 < size <= 4 * 1024 * 1024:
        raise ValueError("Invalid packet size")
    value = json.loads(Read_Exact(connection, size).decode())
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    return value
