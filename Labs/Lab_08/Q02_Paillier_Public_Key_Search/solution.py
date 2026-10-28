# Lab 8 Q2: Paillier-encrypted documents and searchable index
# Educational lab exercise. No user-defined classes are used.

import json
import math
import secrets
import hashlib
from pathlib import Path


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.Util.number import getPrime


def paillier_keys(bits=512):
    """Input: desired modulus size. Generate p/q and compute Paillier parameters with g=n+1.
    Output: (public dictionary n/g, private dictionary lambda/mu). Keep private values secret.
    """
    if bits < 128:
        raise ValueError("Use at least 128 bits for this teaching exercise.")
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        lam = math.lcm(p - 1, q - 1)
        if math.gcd(lam, n) == 1:
            break
    return {"n": n, "g": n + 1}, {"lambda": lam, "mu": pow(lam, -1, n)}


def paillier_encrypt(public, message):
    """Input: public n/g and integer 0<=message<n. Choose fresh random r coprime to n.
    Output: ciphertext g^message * r^n modulo n^2. Same message encrypts differently each time.
    """
    n = public["n"]
    if not isinstance(message, int) or not 0 <= message < n:
        raise ValueError("Message must be an integer in 0..n-1.")
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return pow(public["g"], message, n * n) * pow(r, n, n * n) % (n * n)


def paillier_decrypt(public, private, ciphertext):
    """Input: matching public/private keys and valid ciphertext. Apply L(c^lambda)*mu modulo n.
    Output: plaintext integer modulo n. L(u) means (u-1)//n.
    """
    n = public["n"]
    if not 0 < ciphertext < n * n or math.gcd(ciphertext, n) != 1:
        raise ValueError("Invalid Paillier ciphertext.")
    u = pow(ciphertext, private["lambda"], n * n)
    return ((u - 1) // n) * private["mu"] % n


from Crypto.Util.number import getPrime


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


def text_to_numbers(text, chunk_bytes):
    """Input: text and safe byte-chunk length. Prefix each chunk with byte 1 and encode as integer.
    Output: list of integers for Paillier. Prefix preserves leading zero bytes on decoding.
    """
    data = text.encode()
    return [
        int.from_bytes(b"\x01" + data[i : i + chunk_bytes], "big")
        for i in range(0, len(data), chunk_bytes)
    ]


def numbers_to_text(values):
    """Input: decrypted encoded chunk integers. Remove the one-byte prefix and join bytes.
    Output: original UTF-8 string. Reject invalid marker bytes.
    """
    result = b""
    for value in values:
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if not data or data[0] != 1:
            raise ValueError("Invalid text chunk prefix.")
        result += data[1:]
    return result.decode()


def encrypt_text(public, text):
    """Input: Paillier public key and text. Split into bounded chunks and encrypt each integer.
    Output: list of randomized ciphertext integers. Ordinary Paillier encrypts integers, not strings.
    """
    chunk_bytes = (public["n"].bit_length() - 2) // 8 - 1
    return [paillier_encrypt(public, value) for value in text_to_numbers(text, chunk_bytes)]


def decrypt_text(public, private, ciphertexts):
    """Input: Paillier keys and encrypted text chunks. Decrypt and reconstruct bytes.
    Output: original string. Use only for authorized matching posting lists/documents.
    """
    return numbers_to_text([paillier_decrypt(public, private, value) for value in ciphertexts])


def add_public_document(store, public, search_key, document_id, text):
    """Input: store, Paillier public key, search-token key, ID and text. Add encrypted corpus/index entries.
    Output: updated store. Each posting stores a separately Paillier-encrypted ID, needing no private key to add.
    """
    if not document_id or document_id in store["documents"]:
        raise ValueError("Use a unique nonempty ID.")
    store["documents"][document_id] = encrypt_text(public, text)
    for word in words(text):
        token = keyword_token(search_key, word)
        store["index"].setdefault(token, []).append(encrypt_text(public, document_id))


def search_public(store, public, private, search_key, query):
    """Input: encrypted index, authorized keys and one keyword. Compute stable token and select postings.
    Output: matching IDs, decrypting only their encrypted identifiers. No corpus scan is performed.
    """
    normalized = words(query)
    if len(normalized) != 1:
        raise ValueError("Enter one keyword.")
    token = keyword_token(search_key, normalized.pop())
    return [
        decrypt_text(public, private, ciphertexts) for ciphertexts in store["index"].get(token, [])
    ]


def exercise():
    """Input: menu choices for a Paillier-encrypted corpus and token index.
    Output: ten-document corpus, selected matching IDs/text and persistent encrypted records.
    """
    folder = Path(__file__).resolve().parent / "storage"
    folder.mkdir(exist_ok=True)
    key_path = folder / "keys.json"
    data_path = folder / "corpus.json"
    if not key_path.exists():
        public, private = paillier_keys(512)
        key_path.write_text(
            json.dumps({"public": public, "private": private, "search_key": secrets.token_hex(32)})
        )
        key_path.chmod(0o600)
    keys = json.loads(key_path.read_text())
    public = keys["public"]
    private = keys["private"]
    token_key = bytes.fromhex(keys["search_key"])
    store = (
        json.loads(data_path.read_text()) if data_path.exists() else {"documents": {}, "index": {}}
    )
    while True:
        print("\n1 Create ten documents  2 Add  3 Search  4 Ciphertexts  0 Back")
        choice = input("Operation: ").strip()
        if choice == "0":
            return
        try:
            if choice == "1":
                for doc_id, text in example_documents().items():
                    if doc_id not in store["documents"]:
                        add_public_document(store, public, token_key, doc_id, text)
                print("Document count:", len(store["documents"]))
            elif choice == "2":
                add_public_document(
                    store,
                    public,
                    token_key,
                    ask_text("ID", "doc11"),
                    ask_text("Text", "Another patient document"),
                )
            elif choice == "3":
                query = ask_text("Keyword", "patient")
                encrypted_query = encrypt_text(public, query)
                print("Randomized encrypted query (transport illustration):", encrypted_query)
                ids = search_public(store, public, private, token_key, query)
                print("Matching IDs:", ids)
                if ids:
                    selected = ask_text("Matching ID to decrypt, or all", ids[0])
                    chosen = ids if selected == "all" else [selected]
                    if any(doc_id not in ids for doc_id in chosen):
                        raise ValueError("Select a matching ID.")
                    for doc_id in chosen:
                        print(doc_id, decrypt_text(public, private, store["documents"][doc_id]))
            elif choice == "4":
                print(json.dumps(store, indent=2))
            else:
                print("Invalid choice.")
                continue
            data_path.write_text(json.dumps(store, indent=2))
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
