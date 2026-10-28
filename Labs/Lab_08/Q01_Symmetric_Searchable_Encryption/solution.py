# Lab 8 Q1: Symmetric searchable encryption
# Educational lab exercise. No user-defined classes are used.

import json
import hashlib
from pathlib import Path


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.Cipher import AES
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


import hmac
import re


def words(text):
    """Input: text. Lowercase and extract English alphanumeric keywords consistently.
    Output: set of unique tokens. Use the same normalization for indexing and querying.
    """
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def keyword_token(index_key, word):
    """Input: secret index key and normalized keyword. Compute deterministic HMAC-SHA256 token.
    Output: hex lookup token. Same key/word gives same token without exposing a plain word hash.
    """
    return hmac.new(index_key, word.encode(), hashlib.sha256).hexdigest()


def example_documents():
    """Input: none. Return the ten-document corpus required by the lab.
    Output: dictionary from document IDs to text; edit/add records through the menu.
    """
    texts = [
        "Information security protects patient records",
        "AES encrypts confidential documents",
        "RSA provides public key encryption",
        "Patient diagnosis requires careful review",
        "Paillier enables encrypted addition",
        "Digital signatures detect document tampering",
        "Searchable encryption locates encrypted records",
        "Hospital staff manage patient treatment",
        "Key rotation and expiry control access",
        "Security audits record access events",
    ]
    return {f"doc{i}": text for i, text in enumerate(texts, 1)}


def add_document(store, document_id, text, data_key, index_key):
    """Input: store, unique ID, text and separate data/index keys. Encrypt text and update keyword postings.
    Output: store modified in place. Existing postings are decrypted only for words in this new document.
    """
    if not document_id or document_id in store["documents"]:
        raise ValueError("Document ID must be new.")
    store["documents"][document_id] = seal(text.encode(), data_key)
    for word in words(text):
        token = keyword_token(index_key, word)
        ids = (
            json.loads(open_seal(store["index"][token], data_key))
            if token in store["index"]
            else []
        )
        ids.append(document_id)
        store["index"][token] = seal(json.dumps(ids).encode(), data_key)


def search(store, query, data_key, index_key):
    """Input: encrypted store, one-keyword query and matching keys. Look up deterministic token.
    Output: matching document IDs; decrypt only the matching posting list, not the corpus.
    """
    normalized = words(query)
    if len(normalized) != 1:
        raise ValueError("Enter exactly one keyword.")
    token = keyword_token(index_key, normalized.pop())
    if token not in store["index"]:
        return []
    return json.loads(open_seal(store["index"][token], data_key))


def exercise():
    """Input: persistent SSE menu choices. Build ten documents, add, search or view ciphertext.
    Output: encrypted JSON, matching IDs and only chosen matching documents decrypted.
    """
    folder = Path(__file__).resolve().parent / "storage"
    folder.mkdir(exist_ok=True)
    keys_path = folder / "keys.json"
    store_path = folder / "corpus.json"
    if not keys_path.exists():
        keys_path.write_text(
            json.dumps({"data": get_random_bytes(32).hex(), "index": get_random_bytes(32).hex()})
        )
        keys_path.chmod(0o600)
    keys = json.loads(keys_path.read_text())
    data_key = bytes.fromhex(keys["data"])
    index_key = bytes.fromhex(keys["index"])
    store = (
        json.loads(store_path.read_text())
        if store_path.exists()
        else {"documents": {}, "index": {}}
    )
    while True:
        print(
            "\n1 Create ten-document corpus  2 Add document  3 Search  4 Show encrypted store  0 Back"
        )
        choice = input("Operation: ").strip()
        if choice == "0":
            return
        try:
            if choice == "1":
                for doc_id, text in example_documents().items():
                    if doc_id not in store["documents"]:
                        add_document(store, doc_id, text, data_key, index_key)
                print("Document count:", len(store["documents"]))
            elif choice == "2":
                add_document(
                    store,
                    ask_text("New ID", "doc11"),
                    ask_text("Text", "A new security document"),
                    data_key,
                    index_key,
                )
            elif choice == "3":
                ids = search(store, ask_text("Keyword", "patient"), data_key, index_key)
                print("Matching IDs:", ids)
                if ids:
                    selected = ask_text("Matching ID to decrypt, or all", ids[0])
                    selected_ids = ids if selected == "all" else [selected]
                    if any(doc_id not in ids for doc_id in selected_ids):
                        raise ValueError("Choose only a matching ID.")
                    for doc_id in selected_ids:
                        print(doc_id, open_seal(store["documents"][doc_id], data_key).decode())
            elif choice == "4":
                print(json.dumps(store, indent=2))
            else:
                print("Invalid choice.")
                continue
            store_path.write_text(json.dumps(store, indent=2))
        except (ValueError, KeyError, OSError) as error:
            print("Rejected:", error)


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
