# Lab 8 Q1: Symmetric searchable encryption

## What the manual asks

Create at least ten documents, AES encrypt/decrypt them, build an encrypted inverted index, search it and decrypt returned IDs/documents.

## Start here: the idea in plain English

An inverted index maps each keyword to document IDs containing it. Replace visible words with keyed deterministic HMAC tokens; encrypt each posting list with AES-GCM. Encrypt documents separately. Search computes the same HMAC token, decrypts only the corresponding list of IDs, then decrypts the selected matching documents. Separate data and index keys are stored locally so searches still work after restart. Choose Create corpus, then Search for patient.

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
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `seal(data, key)`

Input: plaintext bytes and AES key. Encrypt and authenticate using AES-GCM.
Output: dictionary containing nonce, tag and ciphertext as hex strings for JSON storage.

### `open_seal(record, key)`

Input: GCM record and matching AES key. Verify the tag while decrypting.
Output: plaintext bytes. Wrong keys or modified data raise ValueError.

### `words(text)`

Input: text. Lowercase and extract English alphanumeric keywords consistently.
Output: set of unique tokens. Use the same normalization for indexing and querying.

### `keyword_token(index_key, word)`

Input: secret index key and normalized keyword. Compute deterministic HMAC-SHA256 token.
Output: hex lookup token. Same key/word gives same token without exposing a plain word hash.

### `example_documents()`

Input: none. Return the ten-document corpus required by the lab.
Output: dictionary from document IDs to text; edit/add records through the menu.

### `add_document(store, document_id, text, data_key, index_key)`

Input: store, unique ID, text and separate data/index keys. Encrypt text and update keyword postings.
Output: store modified in place. Existing postings are decrypted only for words in this new document.

### `search(store, query, data_key, index_key)`

Input: encrypted store, one-keyword query and matching keys. Look up deterministic token.
Output: matching document IDs; decrypt only the matching posting list, not the corpus.

### `exercise()`

Input: persistent SSE menu choices. Build ten documents, add, search or view ciphertext.
Output: encrypted JSON, matching IDs and only chosen matching documents decrypted.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

The manual tries to match freshly randomized AES encryptions; they will not compare equal. This solution uses HMAC for stable lookup and AES-GCM for encrypted contents/posting lists. It is an educational SSE design and leaks repeated-search patterns and result/access patterns. The local key file is owner-only, but the OS user is trusted.
