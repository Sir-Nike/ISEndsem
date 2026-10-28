# Lab 6 additional Q1: RSA encryption, hashing and signatures
# Educational lab exercise. No user-defined classes are used.

import json
import hashlib


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.PublicKey import RSA
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


from Crypto.Signature import pkcs1_15


def sign_message(private_key, message):
    """Input: RSA private key and message bytes. Hash with SHA-256 and sign with PKCS#1 v1.5.
    Output: signature bytes. Use verify_message with the corresponding public key.
    """
    return pkcs1_15.new(private_key).sign(SHA256.new(message))


def verify_message(public_key, message, signature):
    """Input: RSA public key, message bytes and signature bytes. Verify the SHA-256 signature.
    Output: True for a valid signature, False for altered message/signature or wrong key.
    """
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


def exercise():
    """Input: message. Encrypt for receiver, sign as sender, decrypt and verify.
    Output: SHA-256, encrypted record, signature, recovered text and tamper rejection.
    """
    data = ask_text("Message", "Confidential signed message").encode()
    sender = RSA.generate(2048)
    receiver = RSA.generate(2048)
    digest = hashlib.sha256(data).hexdigest()
    signature = sign_message(sender, data)
    record = rsa_hybrid_encrypt(receiver.publickey(), data)
    recovered = rsa_hybrid_decrypt(receiver, record)
    print("SHA-256:", digest, "Signature:", signature.hex())
    print("Encrypted:", json.dumps(record, indent=2), "Recovered:", recovered.decode())
    print("Hash agrees:", hashlib.sha256(recovered).hexdigest() == digest)
    print("Signature valid:", verify_message(sender.publickey(), recovered, signature))
    print("Changed message valid:", verify_message(sender.publickey(), recovered + b"!", signature))
    print(
        "Confidentiality/integrity/authenticity shown. Availability requires separate system measures."
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
