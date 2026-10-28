# Lab 3 additional Q4: Healthcare encryption with EC-ElGamal
# Educational lab exercise. No user-defined classes are used.

import json
import time


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


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
    """Input: patient record text and comma-separated target byte sizes. Benchmark EC-ElGamal.
    Output: envelope, recovered record, timings and equality checks for each size.
    """
    text = ask_text("Patient record", "Patient 101: diagnosis=diabetes; treatment=review")
    key = ECC.generate(curve="P-256")
    record = ec_elgamal_encrypt(key.public_key(), text.encode())
    print("Encrypted record:", json.dumps(record, indent=2))
    print("Recovered:", ec_elgamal_decrypt(key, record).decode())
    sizes = [int(x) for x in ask_text("Benchmark sizes in bytes", "1024,10240").split(",")]
    for size in sizes:
        if not 1 <= size <= 10485760:
            raise ValueError("Size must be in 1..10485760.")
        data = get_random_bytes(size)
        start = time.perf_counter()
        record = ec_elgamal_encrypt(key.public_key(), data)
        enc = time.perf_counter() - start
        start = time.perf_counter()
        recovered = ec_elgamal_decrypt(key, record)
        dec = time.perf_counter() - start
        print(size, "bytes; encrypt s:", enc, "decrypt s:", dec, "verified:", recovered == data)
        assert recovered == data


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
