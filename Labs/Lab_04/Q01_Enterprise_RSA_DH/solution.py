# Lab 4 Q1: Enterprise RSA and Diffie-Hellman communication
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


from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256


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


# RFC 3526 group 14: a fixed standard 2048-bit safe prime, generator 2.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2


def dh_keypair(p=DH_P, g=DH_G):
    """Input: prime and generator (standard defaults). Draw a random private exponent.
    Output: (private, public=g^private mod p). Only the public value is exchanged.
    """
    private = secrets.randbelow((p - 1) // 2 - 2) + 2
    return private, pow(g, private, p)


def dh_shared(private, peer_public, p=DH_P):
    """Input: own private exponent, peer public value and safe prime. Validate the peer.
    Output: SHA-256-derived 32-byte shared key. Both peers get the same key.
    """
    if not 2 <= peer_public <= p - 2 or pow(peer_public, (p - 1) // 2, p) != 1:
        raise ValueError("Invalid Diffie-Hellman public value.")
    secret = pow(peer_public, private, p)
    return hashlib.sha256(secret.to_bytes((p.bit_length() + 7) // 8, "big")).digest()


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


def load_systems(folder):
    """Input: storage directory. Load persisted subsystem keys/status, or start empty.
    Output: registry dictionary. This local teaching program protects files by OS permissions.
    """
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "systems.json"
    return json.loads(path.read_text()) if path.exists() else {}


def save_systems(folder, systems, event):
    """Input: storage directory, registry and audit description. Persist and append audit entry.
    Output: updated owner-only JSON and audit log files; returns nothing.
    """
    path = folder / "systems.json"
    path.write_text(json.dumps(systems, indent=2))
    path.chmod(0o600)
    with (folder / "audit.jsonl").open("a") as log:
        log.write(json.dumps({"time": time.time(), "event": event}) + "\n")


def register_system(systems, name):
    """Input: registry and new subsystem name. Generate RSA-2048 identity/wrapping keys.
    Output: updated registry in place. Existing names are rejected to prevent silent overwrites.
    """
    if not name or name in systems:
        raise ValueError("Use a new nonempty subsystem name.")
    key = RSA.generate(2048)
    systems[name] = {
        "private": key.export_key().decode(),
        "public": key.publickey().export_key().decode(),
        "active": True,
    }


def transfer_document(systems, sender, recipient, message):
    """Input: registry, active sender/recipient names and document bytes. Authenticate DH public values with RSA.
    Output: JSON-safe encrypted envelope, recovered document and validity result. RSA also wraps the derived AES key.
    """
    for name in (sender, recipient):
        if name not in systems or not systems[name]["active"]:
            raise ValueError("Unknown or revoked subsystem: " + name)
    sender_key = RSA.import_key(systems[sender]["private"])
    recipient_key = RSA.import_key(systems[recipient]["private"])
    a, A = dh_keypair()
    b, B = dh_keypair()
    # Bind both public values and identities into the signed exchange transcript.
    transcript = json.dumps(
        {"sender": sender, "recipient": recipient, "A": A, "B": B}, sort_keys=True
    ).encode()
    sig_a = sign_message(sender_key, transcript)
    sig_b = sign_message(recipient_key, transcript)
    if not verify_message(sender_key.publickey(), transcript, sig_a) or not verify_message(
        recipient_key.publickey(), transcript, sig_b
    ):
        raise ValueError("Unauthenticated key exchange.")
    alice = dh_shared(a, B)
    bob = dh_shared(b, A)
    wrapped = rsa_encrypt(recipient_key.publickey(), alice)
    unwrapped = rsa_decrypt(recipient_key, wrapped)
    if unwrapped != bob:
        raise ValueError("RSA-wrapped key disagrees with DH key.")
    envelope = seal(message, alice)
    envelope["wrapped_key"] = wrapped.hex()
    envelope["signature"] = sign_message(sender_key, message).hex()
    envelope["sender"] = sender
    envelope["recipient"] = recipient
    recovered = open_seal(envelope, bob)
    valid = verify_message(sender_key.publickey(), recovered, bytes.fromhex(envelope["signature"]))
    return envelope, recovered, valid


def exercise():
    """Input: repeated menu choices for subsystem registration, listing, transfer and revocation.
    Output: persisted registry, transfer envelopes, verification and audit entries.
    """
    folder = Path(__file__).resolve().parent / "storage"
    systems = load_systems(folder)
    while True:
        print("\n1 Register subsystem  2 List  3 Send document  4 Revoke  0 Back")
        choice = input("Operation: ").strip()
        if choice == "0":
            return
        try:
            if choice == "1":
                name = ask_text("Subsystem name", "Finance")
                register_system(systems, name)
                save_systems(folder, systems, "registered " + name)
            elif choice == "2":
                print({name: record["active"] for name, record in systems.items()})
            elif choice == "3":
                sender = ask_text("Sender", "Finance")
                recipient = ask_text("Recipient", "HR")
                text = ask_text("Document", "Approved financial report")
                envelope, recovered, valid = transfer_document(
                    systems, sender, recipient, text.encode()
                )
                path = folder / f"transfer_{time.time_ns()}.json"
                path.write_text(json.dumps(envelope, indent=2))
                print(
                    "Stored:", path, "Recovered:", recovered.decode(), "Signature verified:", valid
                )
                save_systems(folder, systems, "document transfer " + sender + " to " + recipient)
            elif choice == "4":
                name = ask_text("Subsystem to revoke", "HR")
                systems[name]["active"] = False
                save_systems(folder, systems, "revoked " + name)
            else:
                print("Invalid choice.")
        except (ValueError, KeyError, OSError) as error:
            print("Operation rejected:", error)


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
