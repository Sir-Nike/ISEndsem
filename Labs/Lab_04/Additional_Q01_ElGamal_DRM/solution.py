# Lab 4 additional Q1: ElGamal digital rights management
# Educational lab exercise. No user-defined classes are used.

import json
import time
import secrets
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


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, isPrime


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


def elgamal_keys(bits=256):
    """Input: demonstration modulus bit size. Generate safe prime p=2q+1 and subgroup generator.
    Output: (public dictionary p,g,y; private x). Use 2048+ bits for serious parameters.
    """
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            break
    g = 4
    x = secrets.randbelow(q - 1) + 1
    return {"p": p, "g": g, "y": pow(g, x, p)}, x


def elgamal_encrypt(public, message):
    """Input: ElGamal public parameters and integer 1<=message<p. Randomize and encrypt.
    Output: pair (g^k mod p, message*y^k mod p). Use fresh k for every encryption.
    """
    p, g, y = public["p"], public["g"], public["y"]
    if not 1 <= message < p:
        raise ValueError("ElGamal message must lie in 1..p-1.")
    k = secrets.randbelow(p - 2) + 1
    return pow(g, k, p), (message * pow(y, k, p)) % p


def elgamal_decrypt(public, private, ciphertext):
    """Input: public parameters, private exponent and ciphertext pair. Remove the shared mask.
    Output: original integer. Multiply c2 by the modular inverse of c1^private.
    """
    a, b = ciphertext
    return b * pow(pow(a, private, public["p"]), -1, public["p"]) % public["p"]


def load_drm(folder):
    """Input: storage directory. Load/create master ElGamal key, content catalog and grants.
    Output: state dictionary. The containing OS account is the trusted administrator.
    """
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "drm.json"
    if path.exists():
        return json.loads(path.read_text())
    bits = ask_int("Master ElGamal bits (256 for quick practice; 2048 in prompt)", 256, 256, 4096)
    public, private = elgamal_keys(bits)
    return {
        "public": public,
        "private": private,
        "bits": bits,
        "active": True,
        "created": time.time(),
        "expires": time.time() + 730 * 24 * 3600,
        "contents": {},
        "grants": {},
    }


def save_drm(folder, state, event):
    """Input: directory, DRM state and event. Save owner-only state and append an audit line.
    Output: drm.json and audit.jsonl. Call after encryption, grants, renewals or revocation.
    """
    path = folder / "drm.json"
    path.write_text(json.dumps(state, indent=2))
    path.chmod(0o600)
    with (folder / "audit.jsonl").open("a") as stream:
        stream.write(json.dumps({"time": time.time(), "event": event}) + "\n")


def upload_content(state, content_id, creator, data):
    """Input: DRM state, unique content ID, creator identity and content bytes.
    Output: new encrypted catalog entry in state. ElGamal wraps a random AES-GCM content key.
    """
    if not state["active"] or time.time() >= state["expires"]:
        raise ValueError("Master key inactive or expired.")
    if not content_id or content_id in state["contents"]:
        raise ValueError("Content ID must be new.")
    session = get_random_bytes(16)
    encrypted = seal(data, session)
    encrypted["wrapped_key"] = elgamal_encrypt(state["public"], int.from_bytes(session, "big") + 1)
    encrypted["creator"] = creator
    state["contents"][content_id] = encrypted


def grant_access(state, creator, customer, content_id, seconds):
    """Input: state, creator, customer, content ID and positive duration. Check ownership.
    Output: expiring access grant saved in state. Another creator cannot grant this content.
    """
    if state["contents"][content_id]["creator"] != creator:
        raise ValueError("Only the content creator can manage its access.")
    if seconds <= 0:
        raise ValueError("Duration must be positive.")
    state["grants"].setdefault(customer, {})[content_id] = time.time() + seconds


def view_content(state, customer, content_id):
    """Input: state, customer and content ID. Check master status and per-content grant.
    Output: decrypted content bytes. Deny revoked/expired grants before using the private key.
    """
    if not state["active"] or time.time() >= state["expires"]:
        raise ValueError("Master key revoked or expired.")
    deadline = state["grants"].get(customer, {}).get(content_id, 0)
    if time.time() >= deadline:
        raise ValueError("Customer has no active access grant.")
    record = state["contents"][content_id]
    integer = elgamal_decrypt(state["public"], state["private"], record["wrapped_key"]) - 1
    return open_seal(record, integer.to_bytes(16, "big"))


def rotate_master(state):
    """Input: state. Decrypt only stored content keys and rewrap them under a new ElGamal master.
    Output: updated key pair, active status and two-year expiry; content ciphertext stays intact.
    """
    sessions = {
        cid: elgamal_decrypt(state["public"], state["private"], r["wrapped_key"])
        for cid, r in state["contents"].items()
    }
    public, private = elgamal_keys(state["bits"])
    for cid, value in sessions.items():
        state["contents"][cid]["wrapped_key"] = elgamal_encrypt(public, value)
    state.update(
        {
            "public": public,
            "private": private,
            "active": True,
            "created": time.time(),
            "expires": time.time() + 730 * 24 * 3600,
        }
    )


def exercise():
    """Input: DRM menu choices. Upload, grant, read, revoke, rotate and inspect content.
    Output: persistent encrypted catalog, access checks, recovered content and audit log.
    """
    folder = Path(__file__).resolve().parent / "storage"
    state = load_drm(folder)
    if state["active"] and time.time() >= state["expires"]:
        rotate_master(state)
        save_drm(folder, state, "automatic scheduled renewal")
    while True:
        print(
            "\n1 Upload  2 Grant  3 View  4 Revoke customer/content  5 Revoke master  6 Rotate master  7 List  0 Back"
        )
        choice = input("Operation: ").strip()
        if choice == "0":
            save_drm(folder, state, "closed session")
            return
        try:
            if choice == "1":
                cid = ask_text("Content ID", "book1")
                creator = ask_text("Creator", "Alice")
                upload_content(
                    state, cid, creator, ask_text("Content", "A protected e-book").encode()
                )
            elif choice == "2":
                creator = ask_text("Creator", "Alice")
                customer = ask_text("Customer", "Bob")
                cid = ask_text("Content ID", "book1")
                grant_access(
                    state, creator, customer, cid, ask_int("Access duration seconds", 120, 1)
                )
            elif choice == "3":
                customer = ask_text("Customer", "Bob")
                cid = ask_text("Content ID", "book1")
                print("Content:", view_content(state, customer, cid).decode())
            elif choice == "4":
                creator = ask_text("Creator", "Alice")
                customer = ask_text("Customer", "Bob")
                cid = ask_text("Content ID", "book1")
                if state["contents"][cid]["creator"] != creator:
                    raise ValueError("Creator does not own the content.")
                state["grants"].get(customer, {}).pop(cid, None)
            elif choice == "5":
                state["active"] = False
            elif choice == "6":
                rotate_master(state)
            elif choice == "7":
                print(
                    "Master active:",
                    state["active"],
                    "Expires:",
                    state["expires"],
                    "Contents:",
                    list(state["contents"]),
                )
            else:
                print("Invalid choice.")
                continue
            save_drm(folder, state, "operation " + choice)
        except (ValueError, KeyError, OSError) as error:
            print("Rejected:", error)
            save_drm(folder, state, "rejected operation " + choice)


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
