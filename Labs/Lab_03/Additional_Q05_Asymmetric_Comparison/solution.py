# Lab 3 additional Q5: RSA, curve ElGamal and ECC comparison
# Educational lab exercise. No user-defined classes are used.

import json
import time


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


def rsa_encrypt(public_key, message):
    """Input: RSA public key and short plaintext bytes. Encrypt using RSA-OAEP/SHA-256.
    Output: ciphertext bytes. A 2048-bit key accepts at most 190 plaintext bytes here.
    """
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)


def rsa_decrypt(private_key, ciphertext):
    """Input: RSA private key and OAEP ciphertext. Check padding and recover the message.
    Output: plaintext bytes, or ValueError on invalid ciphertext/key. Use with rsa_encrypt.
    """
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


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


def point_record(point):
    """Input: a PyCryptodome ECC point. Convert public coordinates to JSON-safe integers.
    Output: dictionary with x and y. Use to serialize ephemeral public points.
    """
    return {"x": int(point.x), "y": int(point.y)}


def read_point(record):
    """Input: dictionary of P-256 public coordinates. Validate and construct the point.
    Output: ECC point. Use only with records produced for the same curve.
    """
    return ECC.construct(curve="P-256", point_x=record["x"], point_y=record["y"]).pointQ


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


def ecc_decrypt(private_key, record):
    """Input: recipient P-256 private key and hybrid encrypted record. Recreate ECDH key.
    Output: verified plaintext bytes. Uses the ephemeral public point stored in the record.
    """
    shared = read_point(record["ephemeral"]) * int(private_key.d)
    key = SHA256.new(int(shared.x).to_bytes(32, "big")).digest()
    return open_seal(record, key)


def rsa_hybrid_encrypt(public_key, data):
    """Input: RSA public key and arbitrary-length data. AES-GCM encrypt data and wrap its key.
    Output: JSON-safe encrypted record. RSA handles only the small AES key, not the whole file.
    """
    key = get_random_bytes(32)
    record = seal(data, key)
    record["wrapped_key"] = rsa_encrypt(public_key, key).hex()
    return record


def rsa_hybrid_decrypt(private_key, record):
    """Input: RSA private key and hybrid record. Unwrap the AES key and verify/decrypt data.
    Output: original plaintext bytes. Use with rsa_hybrid_encrypt.
    """
    key = rsa_decrypt(private_key, bytes.fromhex(record["wrapped_key"]))
    return open_seal(record, key)


def ec_elgamal_encrypt(public_key, data):
    """Input: P-256 public key and bytes. ElGamal-encrypt a random curve point, then use it as AES key material.
    Output: JSON-safe C1/C2 points and GCM data. C1=kG and C2=R+kQ hide the random point R.
    """
    random_point = ECC.generate(curve="P-256").pointQ
    ephemeral = ECC.generate(curve="P-256")
    c1 = ephemeral.pointQ
    c2 = random_point + public_key.pointQ * int(ephemeral.d)
    key = SHA256.new(int(random_point.x).to_bytes(32, "big")).digest()
    record = seal(data, key)
    record.update({"c1": point_record(c1), "c2": point_record(c2)})
    return record


def ec_elgamal_decrypt(private_key, record):
    """Input: P-256 private key and EC-ElGamal hybrid record. Recover R=C2-private*C1.
    Output: authenticated plaintext bytes after deriving the same AES key from R.
    """
    random_point = read_point(record["c2"]) + (-(read_point(record["c1"]) * int(private_key.d)))
    key = SHA256.new(int(random_point.x).to_bytes(32, "big")).digest()
    return open_seal(record, key)


def exercise():
    """Input: comma-separated message sizes. Time all three specified hybrid approaches.
    Output: key generation, encryption/decryption times, envelope size and correctness.
    """
    sizes = [int(x) for x in ask_text("Sizes in bytes", "1024,10240").split(",")]
    if any(not 1 <= x <= 10485760 for x in sizes):
        raise ValueError("Sizes must be in 1..10485760.")
    data_by_size = {size: get_random_bytes(size) for size in sizes}
    for name in ("RSA-2048", "EC-ElGamal-P256", "ECDH-P256"):
        start = time.perf_counter()
        key = RSA.generate(2048) if name == "RSA-2048" else ECC.generate(curve="P-256")
        print(name, "key generation s:", time.perf_counter() - start)
        if name == "RSA-2048":
            public, enc, dec = key.publickey(), rsa_hybrid_encrypt, rsa_hybrid_decrypt
        elif name == "EC-ElGamal-P256":
            public, enc, dec = key.public_key(), ec_elgamal_encrypt, ec_elgamal_decrypt
        else:
            public, enc, dec = key.public_key(), ecc_encrypt, ecc_decrypt
        for size, data in data_by_size.items():
            start = time.perf_counter()
            record = enc(public, data)
            encryption = time.perf_counter() - start
            start = time.perf_counter()
            recovered = dec(key, record)
            decryption = time.perf_counter() - start
            assert recovered == data
            print(
                size,
                "bytes; encrypt s:",
                encryption,
                "decrypt s:",
                decryption,
                "stored bytes:",
                len(json.dumps(record).encode()),
                "verified:",
                recovered == data,
            )


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
