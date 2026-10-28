# Lab 8 Q2: Paillier-encrypted documents and searchable index

## What the manual asks

Create ten documents, use Paillier encryption/decryption for data/index, encrypt a query and retrieve matching encrypted IDs.

## Start here: the idea in plain English

Paillier encrypts integers, so encode text in bounded integer chunks and encrypt each chunk. Store encrypted document IDs in posting lists. Randomized Paillier ciphertexts cannot be used directly as equality-search keys; therefore add a keyed deterministic token index. Search uses that token to find the matching encrypted IDs and decrypts only those identifiers and selected documents. The encrypted query is displayed to satisfy the exercise demonstration, but is not falsely used for ciphertext equality.

## How to run

From this question folder, run:

```bash
../../../.venv/bin/python solution.py
```

The program is interactive. If you installed dependencies into another environment, use that environment's Python instead. Read `Labs/README.md` for setup. Paths above assume the environment is in the project root, beside `Labs`.

Press 1 to run an exercise, enter your values or press Enter for the displayed default, and press 0 to exit. Input conversion and validation errors are printed without terminating the interactive menu. Each function can also be imported and called separately.

## Step-by-step solution

1. Start the program and select Run. Read the displayed default inputs before changing them.
2. Follow the input prompts. Text is encoded to bytes when required; numeric inputs are checked before cryptographic operations.
3. Read the `exercise()` function below: it connects the functions in the order needed for this question.
4. Compare the printed output with the expected result, and repeat using a different input.

```python
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
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `paillier_keys(bits)`

Input: desired modulus size. Generate p/q and compute Paillier parameters with g=n+1.
Output: (public dictionary n/g, private dictionary lambda/mu). Keep private values secret.

### `paillier_encrypt(public, message)`

Input: public n/g and integer 0<=message<n. Choose fresh random r coprime to n.
Output: ciphertext g^message * r^n modulo n^2. Same message encrypts differently each time.

### `paillier_decrypt(public, private, ciphertext)`

Input: matching public/private keys and valid ciphertext. Apply L(c^lambda)*mu modulo n.
Output: plaintext integer modulo n. L(u) means (u-1)//n.

### `words(text)`

Input: text. Lowercase and extract English alphanumeric keywords consistently.
Output: set of unique tokens. Use the same normalization for indexing and querying.

### `keyword_token(index_key, word)`

Input: secret index key and normalized keyword. Compute deterministic HMAC-SHA256 token.
Output: hex lookup token. Same key/word gives same token without exposing a plain word hash.

### `example_documents()`

Input: none. Return the ten-document corpus required by the lab.
Output: dictionary from document IDs to text; edit/add records through the menu.

### `text_to_numbers(text, chunk_bytes)`

Input: text and safe byte-chunk length. Prefix each chunk with byte 1 and encode as integer.
Output: list of integers for Paillier. Prefix preserves leading zero bytes on decoding.

### `numbers_to_text(values)`

Input: decrypted encoded chunk integers. Remove the one-byte prefix and join bytes.
Output: original UTF-8 string. Reject invalid marker bytes.

### `encrypt_text(public, text)`

Input: Paillier public key and text. Split into bounded chunks and encrypt each integer.
Output: list of randomized ciphertext integers. Ordinary Paillier encrypts integers, not strings.

### `decrypt_text(public, private, ciphertexts)`

Input: Paillier keys and encrypted text chunks. Decrypt and reconstruct bytes.
Output: original string. Use only for authorized matching posting lists/documents.

### `add_public_document(store, public, search_key, document_id, text)`

Input: store, Paillier public key, search-token key, ID and text. Add encrypted corpus/index entries.
Output: updated store. Each posting stores a separately Paillier-encrypted ID, needing no private key to add.

### `search_public(store, public, private, search_key, query)`

Input: encrypted index, authorized keys and one keyword. Compute stable token and select postings.
Output: matching IDs, decrypting only their encrypted identifiers. No corpus scan is performed.

### `exercise()`

Input: menu choices for a Paillier-encrypted corpus and token index.
Output: ten-document corpus, selected matching IDs/text and persistent encrypted records.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

This is a hybrid public-key-encrypted corpus with a symmetric keyed search token, not a complete formal public-key encryption-with-keyword-search (PEKS) scheme. Paillier alone does not supply a public equality-test trapdoor. The manual’s randomized-ciphertext dictionary lookup cannot work as written. Writers need the public encryption key plus the token key to index new words; private keys are needed only to recover results. The program states this additional assumption explicitly.
