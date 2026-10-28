"""Copyable algorithm recipes for the replacement guides; does not modify any skeleton.
Use functions with the documented adapters. No menus, networking, state files or user-defined classes.
"""

import json
import secrets
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_256, SHA3_512, MD5
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15, pss, DSS, eddsa
from Crypto.Util.Padding import pad, unpad

HASHES = {
    "SHA1": SHA1,
    "SHA224": SHA224,
    "SHA256": SHA256,
    "SHA384": SHA384,
    "SHA512": SHA512,
    "SHA3_256": SHA3_256,
    "SHA3_512": SHA3_512,
    "MD5": MD5,
}


def Make_Symmetric_Key(algorithm="AES", bits=256, mode="GCM"):
    """Input: cipher name, nominal key bits and mode. Output: valid random key bytes.
    AES uses 16/24/32 bytes, doubled for SIV. DES uses 8 bytes; DES3 uses 16/24 with parity adjustment.
    """
    if algorithm == "AES":
        if bits not in (128, 192, 256):
            raise ValueError("AES bits must be 128/192/256")
        return get_random_bytes(bits // 8 * (2 if mode == "SIV" else 1))
    if algorithm == "DES":
        return get_random_bytes(8)
    if algorithm == "DES3":
        if bits not in (128, 192):
            raise ValueError(
                "DES3 input bits must be 128 or 192, including parity bits"
            )
        while True:
            try:
                return DES3.adjust_key_parity(get_random_bytes(bits // 8))
            except ValueError:
                pass
    raise ValueError("Choose AES, DES or DES3")


def Encrypt_Reference(plaintext, key, aad=b"", algorithm="AES", mode="GCM"):
    """Input: bytes/key/AAD and chosen cipher/mode. Output: hex ciphertext/nonce/tag dict.
    For classic IV modes the existing nonce slot stores the IV. Classic modes have an empty tag.
    Supports AES ECB/CBC/CFB/OFB/CTR/OPENPGP/EAX/GCM/CCM/OCB/SIV/KW/KWP; DES/DES3 subset.
    """
    module = {"AES": AES, "DES": DES, "DES3": DES3}[algorithm]
    if not hasattr(module, "MODE_" + mode):
        raise ValueError("Mode is not supported by that cipher")
    identifier = getattr(module, "MODE_" + mode)
    nonce = b""
    tag = b""
    if mode in ("KW", "KWP"):
        cipher = module.new(key, identifier)
        ciphertext = cipher.seal(plaintext)
    elif mode == "ECB":
        ciphertext = module.new(key, identifier).encrypt(
            pad(plaintext, module.block_size)
        )
    elif mode in ("CBC", "CFB", "OFB", "OPENPGP"):
        nonce = get_random_bytes(module.block_size)
        options = {"segment_size": module.block_size * 8} if mode == "CFB" else {}
        cipher = module.new(key, identifier, iv=nonce, **options)
        ciphertext = cipher.encrypt(
            pad(plaintext, module.block_size) if mode == "CBC" else plaintext
        )
        if mode == "OPENPGP":
            length = module.block_size + 2
            nonce, ciphertext = ciphertext[:length], ciphertext[length:]
    elif mode == "CTR":
        nonce = get_random_bytes(module.block_size // 2)
        ciphertext = module.new(key, identifier, nonce=nonce, initial_value=0).encrypt(
            plaintext
        )
    else:
        # A 12-byte nonce is valid for these AES modes; EAX also supports it for DES/DES3.
        nonce = get_random_bytes(12)
        cipher = module.new(key, identifier, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"ciphertext": ciphertext.hex(), "nonce": nonce.hex(), "tag": tag.hex()}


def Decrypt_Reference(envelope, key, aad=b"", algorithm="AES", mode="GCM"):
    """Input: saved hex envelope, same key/AAD/algorithm/mode. Output: recovered bytes or error.
    Call only after the skeleton's outer signature/hash checks. AEAD authenticates before returning.
    """
    module = {"AES": AES, "DES": DES, "DES3": DES3}[algorithm]
    identifier = getattr(module, "MODE_" + mode)
    ciphertext = bytes.fromhex(envelope["ciphertext"])
    nonce, tag = bytes.fromhex(envelope["nonce"]), bytes.fromhex(envelope["tag"])
    if mode in ("KW", "KWP"):
        return module.new(key, identifier).unseal(ciphertext)
    if mode == "ECB":
        return unpad(module.new(key, identifier).decrypt(ciphertext), module.block_size)
    if mode in ("CBC", "CFB", "OFB", "OPENPGP"):
        options = {"segment_size": module.block_size * 8} if mode == "CFB" else {}
        result = module.new(key, identifier, iv=nonce, **options).decrypt(ciphertext)
        return unpad(result, module.block_size) if mode == "CBC" else result
    if mode == "CTR":
        return module.new(key, identifier, nonce=nonce, initial_value=0).decrypt(
            ciphertext
        )
    cipher = module.new(key, identifier, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def Hash_Reference(data, name="SHA256"):
    """Input: bytes and named hash. Output: hex digest. This does not change OAEP/HKDF/audit hashes."""
    return HASHES[name].new(data).hexdigest()


def Generate_Signing_Keys(scheme="RSA-PSS"):
    """Input: RSA-PSS/RSA-v1_5/DSA/ECDSA/Ed25519/Ed448. Output: private/public PEM strings.
    Skeleton identity import/export/fingerprint/registration code must be adapted from ElGamal dicts.
    """
    if scheme.startswith("RSA"):
        key = RSA.generate(2048)
    elif scheme == "DSA":
        key = DSA.generate(2048)
    elif scheme == "ECDSA":
        key = ECC.generate(curve="P-256")
    elif scheme in ("Ed25519", "Ed448"):
        key = ECC.generate(curve=scheme)
    else:
        raise ValueError("Unsupported signature scheme")
    if scheme.startswith("RSA") or scheme == "DSA":
        return key.export_key().decode(), key.public_key().export_key().decode()
    return key.export_key(format="PEM"), key.public_key().export_key(format="PEM")


def Sign_Reference(data, private_pem, scheme="RSA-PSS", hash_name="SHA256"):
    """Input: message bytes, private PEM, scheme and intended signature hash. Output: signature hex.
    Pure EdDSA signs bytes directly; its internal hash is fixed by its algorithm, not hash_name.
    """
    if scheme.startswith("RSA"):
        key = RSA.import_key(private_pem)
        signer = pss if scheme == "RSA-PSS" else pkcs1_15
        return signer.new(key).sign(HASHES[hash_name].new(data)).hex()
    if scheme in ("DSA", "ECDSA"):
        key = (
            DSA.import_key(private_pem)
            if scheme == "DSA"
            else ECC.import_key(private_pem)
        )
        return (
            DSS.new(key, "deterministic-rfc6979", encoding="der")
            .sign(HASHES[hash_name].new(data))
            .hex()
        )
    if scheme in ("Ed25519", "Ed448"):
        return eddsa.new(ECC.import_key(private_pem), "rfc8032").sign(data).hex()
    raise ValueError("Unsupported signature scheme")


def Verify_Reference(data, signature, public_pem, scheme="RSA-PSS", hash_name="SHA256"):
    """Input: same bytes, hex signature, trusted public PEM, scheme/hash. Output: bool.
    Invalid signatures return False; importing an untrusted public key does not establish its identity.
    """
    try:
        raw = bytes.fromhex(signature)
        if scheme.startswith("RSA"):
            verifier = pss if scheme == "RSA-PSS" else pkcs1_15
            verifier.new(RSA.import_key(public_pem)).verify(
                HASHES[hash_name].new(data), raw
            )
        elif scheme in ("DSA", "ECDSA"):
            key = (
                DSA.import_key(public_pem)
                if scheme == "DSA"
                else ECC.import_key(public_pem)
            )
            DSS.new(key, "deterministic-rfc6979", encoding="der").verify(
                HASHES[hash_name].new(data), raw
            )
        elif scheme in ("Ed25519", "Ed448"):
            eddsa.new(ECC.import_key(public_pem), "rfc8032").verify(data, raw)
        else:
            return False
        return True
    except (ValueError, TypeError, KeyError):
        return False


def Wrap_ECC(key, receiver_public_pem):
    """Input: session key bytes and recipient ECDH-capable public PEM. Output: JSON text for encrypted_key.
    Fresh ephemeral ECDH -> HKDF-SHA256 -> AES-KWP wraps the existing session key; no RSA is needed.
    """
    public = ECC.import_key(receiver_public_pem)
    ephemeral = ECC.generate(curve=public.curve)
    derive = lambda raw: HKDF(raw, 32, b"", SHA256, context=b"exam-ecc-wrap-v1")
    wrapping_key = key_agreement(static_priv=ephemeral, static_pub=public, kdf=derive)
    return json.dumps(
        {
            "ephemeral_public": ephemeral.public_key().export_key(format="PEM"),
            "wrapped_key": AES.new(wrapping_key, AES.MODE_KWP).seal(key).hex(),
        }
    )


def Unwrap_ECC(text, receiver_private_pem):
    """Input: JSON wrap text and matching recipient private PEM. Output: original session-key bytes.
    Rebuild ECDH with saved ephemeral public key; HKDF and authenticated unwrap must match Wrap_ECC.
    """
    record = json.loads(text)
    derive = lambda raw: HKDF(raw, 32, b"", SHA256, context=b"exam-ecc-wrap-v1")
    wrapping_key = key_agreement(
        static_priv=ECC.import_key(receiver_private_pem),
        static_pub=ECC.import_key(record["ephemeral_public"]),
        kdf=derive,
    )
    return AES.new(wrapping_key, AES.MODE_KWP).unseal(
        bytes.fromhex(record["wrapped_key"])
    )


def Wrap_ElGamal(key, public):
    """Input: session key bytes and p,g,y dict with p larger than its integer encoding.
    Output: JSON text c1/c2/byte-length for encrypted_key. Textbook lab construction; outer signature required.
    """
    p, g, y = (int(public[k]) for k in ("p", "g", "y"))
    message = int.from_bytes(key, "big")
    if not 1 <= message < p:
        raise ValueError("Key integer must fit 1..p-1; use a larger modulus")
    nonce = secrets.randbelow(p - 2) + 1
    return json.dumps(
        {
            "c1": str(pow(g, nonce, p)),
            "c2": str(message * pow(y, nonce, p) % p),
            "length": len(key),
        }
    )


def Unwrap_ElGamal(text, private):
    """Input: JSON c1/c2/length text and private p,g,x dict. Output: original key bytes, retaining leading zeros."""
    record = json.loads(text)
    p, x = int(private["p"]), int(private["x"])
    c1, c2 = int(record["c1"]), int(record["c2"])
    if not 0 < c1 < p or not 0 < c2 < p or not 1 <= record["length"] <= 128:
        raise ValueError("Invalid ElGamal wrapper")
    value = c2 * pow(pow(c1, x, p), -1, p) % p
    return value.to_bytes(record["length"], "big")
