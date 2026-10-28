import json
import time
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


from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def rsa_encrypt(public_key, message):
    """Input: RSA public key and short plaintext bytes. Encrypt using RSA-OAEP/SHA-256.
    Output: ciphertext bytes. A 2048-bit key accepts at most 190 plaintext bytes here.
    """
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)


def seal(data, key):
    """Input: plaintext bytes and AES key. Encrypt and authenticate using AES-GCM.
    Output: dictionary containing nonce, tag and ciphertext as hex strings for JSON storage.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {"nonce": cipher.nonce.hex(), "tag": tag.hex(), "ciphertext": ciphertext.hex()}


def point_record(point):
    """Input: a PyCryptodome ECC point. Convert public coordinates to JSON-safe integers.
    Output: dictionary with x and y. Use to serialize ephemeral public points.
    """
    return {"x": int(point.x), "y": int(point.y)}


def ecc_encrypt(public_key, data):
    """Input: recipient P-256 public key and plaintext bytes. Derive an AES key with ephemeral ECDH.
    Output: JSON-safe GCM record plus ephemeral public point. Use ecc_decrypt to recover it.
    """
    ephemeral = ECC.generate(curve="P-256")
    shared = public_key.pointQ * int(ephemeral.d)
    key = SHA256.new(int(shared.x).to_bytes(32, "big")).digest()
    record = seal(data, key)
    record["ephemeral"] = point_record(ephemeral.pointQ)
    return record


def rsa_hybrid_encrypt(public_key, data):
    """Input: RSA public key and arbitrary-length data. AES-GCM encrypt data and wrap its key.
    Output: JSON-safe encrypted record. RSA handles only the small AES key, not the whole file.
    """
    key = get_random_bytes(32)
    record = seal(data, key)
    record["wrapped_key"] = rsa_encrypt(public_key, key).hex()
    return record


import socket
import struct


def receive_exact(connection, count):
    """Input: connected socket and required byte count. Read until all bytes arrive.
    Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.
    """
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ValueError("Connection closed before a complete message arrived.")
        data.extend(part)
    return bytes(data)


def send_json(connection, record):
    """Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
    Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.
    """
    data = json.dumps(record).encode()
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Frame exceeds 2 MB teaching limit.")
    connection.sendall(struct.pack("!I", len(data)) + data)


def receive_json(connection):
    """Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
    Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.
    """
    size = struct.unpack("!I", receive_exact(connection, 4))[0]
    if size > 2 * 1024 * 1024:
        raise ValueError("Incoming frame too large.")
    return json.loads(receive_exact(connection, size))


def transfer_file(host, port, scheme, data):
    """Input: server address, RSA/ECC selection and plaintext file bytes. Encrypt locally and send chunked envelope.
    Output: server reply plus local encryption time. Compare plaintext digests to verify exact recovery.
    """
    with socket.create_connection((host, port), timeout=30) as connection:
        send_json(connection, {"scheme": scheme})
        response = receive_json(connection)
        public = (
            RSA.import_key(response["public"])
            if scheme == "RSA"
            else ECC.import_key(response["public"])
        )
        start = time.perf_counter()
        record = rsa_hybrid_encrypt(public, data) if scheme == "RSA" else ecc_encrypt(public, data)
        encryption = time.perf_counter() - start
        ciphertext = record.pop("ciphertext")
        chunks = [ciphertext[i : i + 131072] for i in range(0, len(ciphertext), 131072)] or [""]
        send_json(connection, {"envelope": record, "chunks": len(chunks)})
        for part in chunks:
            send_json(connection, {"data": part})
        reply = receive_json(connection)
    verified = reply["bytes"] == len(data) and reply["sha256"] == hashlib.sha256(data).hexdigest()
    if not verified:
        raise ValueError("Server recovery digest/length mismatch.")
    print(
        scheme,
        len(data),
        "bytes; keygen s:",
        response["keygen_seconds"],
        "encrypt s:",
        encryption,
        "decrypt s:",
        reply["decrypt_seconds"],
        "verified:",
        verified,
    )
    return reply


def exercise():
    """Input: server address, optional real file path or generated sizes, and scheme list.
    Output: real TCP transfers and verified timing rows for RSA/ECC; start server.py first.
    """
    host = ask_text("Server host", "127.0.0.1")
    port = ask_int("Port", 5034, 1024, 65535)
    path = ask_text("File path, or generated", "generated")
    if path == "generated":
        sizes = [
            int(x) for x in ask_text("Generated sizes in bytes", "1048576,10485760").split(",")
        ]
        if any(not 1 <= size <= 20 * 1024 * 1024 for size in sizes):
            raise ValueError("Use sizes in 1..20 MB.")
        datasets = [get_random_bytes(size) for size in sizes]
    else:
        data = Path(path).read_bytes()
        if len(data) > 20 * 1024 * 1024:
            raise ValueError("Maximum file size is 20 MB.")
        datasets = [data]
    schemes = [
        word.strip().upper() for word in ask_text("Schemes, comma separated", "RSA,ECC").split(",")
    ]
    if any(word not in ("RSA", "ECC") for word in schemes):
        raise ValueError("Use RSA and/or ECC.")
    print("Server must accept", len(schemes) * len(datasets), "connections for this run.")
    for data in datasets:
        for scheme in schemes:
            transfer_file(host, port, scheme, data)


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
