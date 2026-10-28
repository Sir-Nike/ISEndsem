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


def rsa_decrypt(private_key, ciphertext):
    """Input: RSA private key and OAEP ciphertext. Check padding and recover the message.
    Output: plaintext bytes, or ValueError on invalid ciphertext/key. Use with rsa_encrypt.
    """
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


def open_seal(record, key):
    """Input: GCM record and matching AES key. Verify the tag while decrypting.
    Output: plaintext bytes. Wrong keys or modified data raise ValueError.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(record["nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(record["ciphertext"]), bytes.fromhex(record["tag"])
    )


def read_point(record):
    """Input: dictionary of P-256 public coordinates. Validate and construct the point.
    Output: ECC point. Use only with records produced for the same curve.
    """
    return ECC.construct(curve="P-256", point_x=record["x"], point_y=record["y"]).pointQ


def ecc_decrypt(private_key, record):
    """Input: recipient P-256 private key and hybrid encrypted record. Recreate ECDH key.
    Output: verified plaintext bytes. Uses the ephemeral public point stored in the record.
    """
    shared = read_point(record["ephemeral"]) * int(private_key.d)
    key = SHA256.new(int(shared.x).to_bytes(32, "big")).digest()
    return open_seal(record, key)


def rsa_hybrid_decrypt(private_key, record):
    """Input: RSA private key and hybrid record. Unwrap the AES key and verify/decrypt data.
    Output: original plaintext bytes. Use with rsa_hybrid_encrypt.
    """
    key = rsa_decrypt(private_key, bytes.fromhex(record["wrapped_key"]))
    return open_seal(record, key)


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


def receive_file(connection, folder):
    """Input: connected client and output directory. Exchange public key, receive encrypted chunks and decrypt.
    Output: stored recovered file and a digest/timing reply; no plaintext file contents cross TCP.
    """
    request = receive_json(connection)
    scheme = request["scheme"]
    if scheme not in ("RSA", "ECC"):
        raise ValueError("Choose RSA or ECC.")
    start = time.perf_counter()
    key = RSA.generate(2048) if scheme == "RSA" else ECC.generate(curve="P-256")
    generation = time.perf_counter() - start
    public = key.publickey() if scheme == "RSA" else key.public_key()
    send_json(
        connection,
        {
            "public": (
                public.export_key().decode() if scheme == "RSA" else public.export_key(format="PEM")
            ),
            "keygen_seconds": generation,
        },
    )
    header = receive_json(connection)
    count = header["chunks"]
    if not isinstance(count, int) or not 1 <= count <= 400:
        raise ValueError("Invalid encrypted chunk count.")
    parts = []
    total = 0
    for _ in range(count):
        part = receive_json(connection)["data"]
        bytes.fromhex(part)
        total += len(part) // 2
        if total > 20 * 1024 * 1024:
            raise ValueError("Encrypted file exceeds 20 MB.")
        parts.append(part)
    record = header["envelope"]
    record["ciphertext"] = "".join(parts)
    start = time.perf_counter()
    data = rsa_hybrid_decrypt(key, record) if scheme == "RSA" else ecc_decrypt(key, record)
    decryption = time.perf_counter() - start
    path = folder / f"{scheme}_{time.time_ns()}.received.bin"
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    send_json(
        connection,
        {
            "bytes": len(data),
            "sha256": digest,
            "decrypt_seconds": decryption,
            "saved_name": path.name,
        },
    )
    print("Received:", scheme, len(data), "bytes; decrypt s:", decryption, "saved:", path)


def exercise():
    """Input: host/port and number of files to accept. Run the RSA/ECC encrypted file receiver.
    Output: decrypted files in received_files and per-transfer timing/digest responses.
    """
    host = ask_text("Bind host", "127.0.0.1")
    port = ask_int("Port", 5034, 1024, 65535)
    count = ask_int("Transfers before returning (2 sizes x 2 schemes = 4)", 4, 1, 100)
    folder = Path(__file__).resolve().parent / "received_files"
    folder.mkdir(exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        listener.settimeout(60)
        print("Listening on", host, port, flush=True)
        for _ in range(count):
            connection, address = listener.accept()
            with connection:
                connection.settimeout(30)
                try:
                    receive_file(connection, folder)
                except (ValueError, KeyError, TypeError, OSError) as error:
                    print("Rejected transfer:", error)


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
