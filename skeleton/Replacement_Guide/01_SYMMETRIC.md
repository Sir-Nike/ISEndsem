# Symmetric encryption replacement guide

## 1. The interface to preserve

Every skeleton calls the payload operations in this form:

```python
envelope = Encrypt(plaintext_bytes, key_bytes, Canonical(metadata))
plaintext_bytes = Decrypt(envelope, key_bytes, Canonical(metadata))
```

The saved envelope needs these existing keys:

```python
{"ciphertext": "hex text", "nonce": "hex text", "tag": "hex text"}
```

The current files are ciphertext.txt, nonce.txt and tag.txt. To minimize edits, keep these fields even for a different mode. Put an IV in the nonce slot for CBC/CFB/OFB/OpenPGP and document that meaning. Put an empty string in unused slots. Empty text files read back as empty strings, which bytes.fromhex accepts. If the question requires iv.txt instead, rename the field/file in BOTH write/read functions and packet construction; do not merely rename the disk file.

The outer hash and signature cover all three fields and metadata. Classic modes do not authenticate AAD themselves; keep the skeleton's verify-before-decrypt order.

## 2. Worked replacement: AES-256-GCM to AES-192-CBC

Copy these imports and three functions into the algorithm file identified by your per-skeleton guide:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def Generate_Symmetric_Key():
    # No input; fresh 24-byte AES-192 key; return bytes.
    return get_random_bytes(24)

def Encrypt(plaintext, key, aad):
    # aad stays in the interface; CBC itself cannot authenticate it.
    # The outer record signature must cover this same metadata.
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return {"ciphertext": ciphertext.hex(), "nonce": iv.hex(), "tag": ""}

def Decrypt(envelope, key, aad):
    # Call after the outer hash/signature/metadata checks pass.
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex(envelope["nonce"]))
    padded = cipher.decrypt(bytes.fromhex(envelope["ciphertext"]))
    return unpad(padded, AES.block_size)
```

Then change Metadata's cipher label to AES-192-CBC. The original Encrypt/Decrypt functions reject keys whose length is not 32: replacing both functions removes that old restriction. Keep RSA wrapping unchanged, since it can carry a 24-byte key. Sender signing, role menus and input encoding stay. Create a new record through the menu; old GCM records are not CBC records.

For AES-128 use a 16-byte key. For AES-256-CBC use 32 bytes. AES's block size stays 16 bytes for all three key sizes. Padding is about the block size, not key size.

## 3. Worked replacement: AES-GCM to AES-ECB

Use the same imports as above; choose the desired valid AES key length. Replace Encrypt/Decrypt with:

```python
def Encrypt(plaintext, key, aad):
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
    return {"ciphertext": ciphertext.hex(), "nonce": "", "tag": ""}

def Decrypt(envelope, key, aad):
    padded = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(envelope["ciphertext"]))
    return unpad(padded, 16)
```

Change the Metadata label to the requested AES size plus ECB. There is no IV or GCM tag. ECB exposes repeated-block patterns; use it when the exam specifically asks for it. The signature is still required before decryption. PKCS#7 adds a whole block when input is already block-aligned; unpad is still necessary.

## 4. Complete mode matrix

These are APIs available in the installed PyCryptodome. The current lab mode benchmark covers the first five classic modes; the table also covers additional library modes. API details: [classic modes](https://www.pycryptodome.org/src/cipher/classic), [modern modes](https://www.pycryptodome.org/src/cipher/modern), [AES constructor](https://www.pycryptodome.org/src/cipher/aes).

| Mode | AES | DES/3DES | Saved parameter | Padding and authentication |
| --- | --- | --- | --- | --- |
| ECB | yes | yes | none | pad/unpad full blocks; outer signature |
| CBC | yes | yes | unpredictable IV, one block | pad/unpad; outer signature |
| CFB | yes | yes | IV, one block; matching segment_size | no padding; outer signature |
| OFB | yes | yes | IV, one block | no padding; outer signature |
| CTR | yes | yes | nonce and agreed counter layout/start | no padding; outer signature |
| OPENPGP | yes | yes | encrypted IV prefix, block_size+2 | no padding; outer signature; not a complete GnuPG message |
| EAX | yes | yes | nonce and tag | AEAD, no padding |
| GCM | yes | no | nonce and tag | AEAD, no padding |
| CCM | yes | no | nonce and tag; message-size limits | AEAD, no padding |
| OCB | yes | no | nonce and tag | AEAD, use encrypt_and_digest/decrypt_and_verify |
| SIV | yes | no | optional nonce and tag | doubled key length; AEAD |
| KW | yes | no | wrapped bytes, no separate IV/tag | specialized key wrap, input at least 16 bytes and multiple of 8 |
| KWP | yes | no | wrapped bytes, no separate IV/tag | specialized padded key wrap, nonempty bytes |

KW/KWP are key-wrapping operations, not ordinary arbitrary-text modes. The recipe supports them to show the API, but do not route arbitrary descriptions into KW. Prefer them inside Encrypt_Key after establishing a separate key-encryption key. An outer signature must bind their surrounding metadata.

## 5. Use the tested generic recipes

[replacement_recipes.py](replacement_recipes.py) contains Make_Symmetric_Key, Encrypt_Reference and Decrypt_Reference. Copy those three functions and their required imports into the exam copy, then add these wrappers:

```python
PAYLOAD_ALGORITHM = "AES"
PAYLOAD_MODE = "CTR"
PAYLOAD_BITS = 256

def Generate_Symmetric_Key():
    return Make_Symmetric_Key(PAYLOAD_ALGORITHM, PAYLOAD_BITS, PAYLOAD_MODE)

def Encrypt(data, key, aad):
    return Encrypt_Reference(data, key, aad, PAYLOAD_ALGORITHM, PAYLOAD_MODE)

def Decrypt(envelope, key, aad):
    return Decrypt_Reference(envelope, key, aad, PAYLOAD_ALGORITHM, PAYLOAD_MODE)
```

Update Metadata to AES-256-CTR. This is an algorithm adapter, not a user menu: choose constants matching the question. Copy the implementations rather than adding a new file dependency if you want one exam script.

The recipe covers the table, with these choices:

- CBC/ECB use PKCS#7. CFB/OFB/CTR/OpenPGP and AEAD do not pad.
- CFB uses a full-block segment: 128 bits for AES, 64 for DES/3DES. PyCryptodome's default CFB segment is 8 bits; match both sides and the question. A lab function using default CFB8 is not interchangeable with CFB128.
- CTR uses a half-block nonce and initial_value=0 on both sides. If the question supplies another start/layout, save it in signed metadata or an additional field and reconstruct it exactly. Never reuse a key/nonce/counter stream.
- OpenPGP's first encryption output includes the encrypted IV prefix. Store its first block_size+2 bytes in nonce and the remainder in ciphertext. Decryption receives that encrypted prefix as iv. For AES this prefix is 18 bytes; for DES/3DES it is 10. A normal raw IV is not the decryption parameter.
- AEAD uses a fresh 12-byte nonce and 16-byte tag by default for AES. DES/3DES EAX has a tag bounded by its 8-byte block. update(aad) and decrypt_and_verify remain paired. The chosen CCM 12-byte nonce limits one message to less than 2^24 bytes; adapt the nonce length/declared lengths for larger specified inputs.
- SIV generates 32/48/64 bytes for nominal AES-128/192/256-SIV. Its key is split internally; do not pass a normal 16/24/32-byte key for the corresponding nominal size. The recipe uses a nonce; deterministic SIV omits nonce on BOTH construction calls and keeps the field empty.

A change in nonce/tag length is not a change in plaintext encoding. Keep text.encode('utf-8') before encryption and decode only after successful verification.

## 6. DES and Triple DES

Select DES or DES3 in the recipe and update Metadata. DES uses 8 key bytes, 8-byte blocks. DES3 input key files have 16 or 24 bytes including parity; use DES3.adjust_key_parity and regenerate if the key degenerates to single DES. The bit arguments 128/192 in Make_Symmetric_Key describe those input sizes including parity, not 128/192 effective security bits.

For example DES3-CBC:

```python
PAYLOAD_ALGORITHM = "DES3"
PAYLOAD_MODE = "CBC"
PAYLOAD_BITS = 192
```

Use the three wrappers above. RSA key wrapping still handles these shorter session keys. The classic-mode padding block is now 8, which the generic recipe gets from module.block_size. DES has no GCM; selecting it must be rejected rather than silently doing another mode. These are lab/legacy exercises.

## 7. ChaCha20, Salsa20 and ChaCha20-Poly1305

If an additional question specifies a stream cipher, retain the dictionary interface. Crypto.Cipher.ChaCha20 and Salsa20 encrypt/decrypt bytes without padding, with saved nonce and an empty tag; keep the outer signature. ChaCha20 supports different nonce forms, so choose one documented form and reconstruct it identically. ChaCha20_Poly1305 uses a 32-byte key, nonce, update(aad), encrypt_and_digest and decrypt_and_verify. Save its tag. Its interface is like GCM, but its constructor/module and Metadata label change. These are optional library extensions rather than claims about extra existing lab folders.

## 8. What stays and what changes in the files

If you preserve ciphertext/nonce/tag text slots, storage functions need no edits. If you add a mode-specific field, update packet construction, write/read routines, verification schema checks (especially Submit), canonical signing bytes and tampering targets. Merely writing a new iv.txt does not make it part of the verified package.

A non-AEAD replacement loses GCM's tag check, so the outer signature/hash checks are essential. They already happen before Decrypt in the skeletons. Wrong ciphertext must not be made acceptable by recomputing the saved hash. Tests should include empty, short, aligned and binary input; a restart; modified metadata; and an altered signature.

## Lab sources to copy from

- [AES/DES modes: encrypt_bytes and decrypt_bytes](../../Labs/Lab_02/Additional_Q01_Modes_Benchmark_Plot/solution.py): returns parameter and ciphertext; adapt tuple outputs to the envelope.
- [DES](../../Labs/Lab_02/Q01_DES/solution.py), [AES-128](../../Labs/Lab_02/Q02_AES_128/solution.py), [3DES](../../Labs/Lab_02/Q04_Triple_DES/solution.py), [AES-256](../../Labs/Lab_02/Additional_Q03_AES_256/solution.py).
- [DES-CBC](../../Labs/Lab_02/Additional_Q04_DES_CBC/solution.py), [AES-CTR](../../Labs/Lab_02/Additional_Q05_AES_CTR/solution.py).
- [AES-192 round tracing](../../Labs/Lab_02/Q05_AES_192_Round_Trace/solution.py): if intermediate rounds are required, a one-call library adapter does not satisfy that requirement. Copy the trace/round functions as well and retain their output.
