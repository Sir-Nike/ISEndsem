# Lab 3: ECC encryption of Secure Transactions
# Educational lab exercise. No user-defined classes are used.

import json


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


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


def exercise():
    """Input: text message. Demonstrate P-256 ECDH plus AES-GCM encryption.
    Output: serialized encrypted record and recovered text; private scalar stays local.
    """
    text = ask_text("Message", "Secure Transactions")
    key = ECC.generate(curve="P-256")
    encrypted = ecc_encrypt(key.public_key(), text.encode())
    recovered = ecc_decrypt(key, encrypted)
    print("Public point:", point_record(key.pointQ))
    print("Encrypted record:", json.dumps(encrypted, indent=2))
    print("Recovered:", recovered.decode(), "Verified:", recovered == text.encode())


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
