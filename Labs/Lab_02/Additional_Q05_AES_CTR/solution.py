# Lab 2 AES-CTR with a nonce
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def parse_key(text, algorithm):
    """Input: key written as hex:... or text:..., plus AES/DES/3DES algorithm name.
    Output: validated key bytes. Explicit prefixes prevent hex text being misread as ASCII.
    """
    if text.startswith("hex:"):
        key = bytes.fromhex(text[4:])
    elif text.startswith("text:"):
        key = text[5:].encode()
    else:
        raise ValueError("Prefix the key with hex: or text:.")
    allowed = {"AES": (16, 24, 32), "DES": (8,), "3DES": (16, 24)}
    if len(key) not in allowed[algorithm]:
        raise ValueError(f"{algorithm} needs {allowed[algorithm]} bytes, received {len(key)}.")
    if algorithm == "3DES":
        key = DES3.adjust_key_parity(key)
    return key


def encrypt_bytes(data, key, algorithm="AES", mode="CBC", parameter=None):
    """Input: plaintext bytes, key bytes, algorithm, mode, optional IV/nonce.
    Output: (IV-or-nonce, ciphertext). Pad ECB/CBC; CTR/CFB/OFB accept any byte length.
    Use the returned parameter unchanged when decrypting.
    """
    module = {"AES": AES, "DES": DES, "3DES": DES3}[algorithm]
    mode = mode.upper()
    if mode == "ECB":
        cipher = module.new(key, module.MODE_ECB)
        return b"", cipher.encrypt(pad(data, module.block_size))
    if mode == "CTR":
        nonce = parameter if parameter is not None else get_random_bytes(module.block_size // 2)
        cipher = module.new(key, module.MODE_CTR, nonce=nonce)
        return nonce, cipher.encrypt(data)
    if mode not in ("CBC", "CFB", "OFB"):
        raise ValueError("Use ECB, CBC, CFB, OFB or CTR.")
    iv = parameter if parameter is not None else get_random_bytes(module.block_size)
    options = {"iv": iv}
    if mode == "CFB":
        options["segment_size"] = module.block_size * 8
    cipher = module.new(key, getattr(module, "MODE_" + mode), **options)
    return iv, cipher.encrypt(pad(data, module.block_size) if mode == "CBC" else data)


def decrypt_bytes(parameter, ciphertext, key, algorithm="AES", mode="CBC"):
    """Input: stored IV/nonce, ciphertext, original key, algorithm and mode.
    Output: recovered plaintext bytes. Use exactly the same settings as encryption.
    """
    module = {"AES": AES, "DES": DES, "3DES": DES3}[algorithm]
    mode = mode.upper()
    options = {}
    if mode == "CTR":
        options["nonce"] = parameter
    elif mode != "ECB":
        options["iv"] = parameter
    if mode == "CFB":
        options["segment_size"] = module.block_size * 8
    cipher = module.new(key, getattr(module, "MODE_" + mode), **options)
    plain = cipher.decrypt(ciphertext)
    return unpad(plain, module.block_size) if mode in ("CBC", "ECB") else plain


def show_round_trip(message, key, algorithm="AES", mode="CBC", parameter=None):
    """Input: text message and cipher settings. Encrypt, print and decrypt it.
    Output: ciphertext bytes; also print IV/nonce, recovered text and equality check.
    """
    iv, ciphertext = encrypt_bytes(message.encode(), key, algorithm, mode, parameter)
    recovered = decrypt_bytes(iv, ciphertext, key, algorithm, mode)
    print("Algorithm:", algorithm, "Mode:", mode, "Key bytes:", len(key))
    print("IV/nonce:", iv.hex(), "Ciphertext:", ciphertext.hex())
    print("Recovered:", recovered.decode(), "Verified:", recovered == message.encode())
    return ciphertext


def exercise():
    """Input: message, prefixed key, and prefixed IV/nonce. Demonstrate the specified mode.
    Output: ciphertext, recovered message and equality check.
    """
    message = ask_text("Message", "Cryptography Lab Exercise")
    key = parse_key(ask_text("Key", "hex:0123456789ABCDEF0123456789ABCDEF"), "AES")
    raw = ask_text("IV/nonce", "hex:0000000000000000")
    if raw.startswith("hex:"):
        parameter = bytes.fromhex(raw[4:])
    elif raw.startswith("text:"):
        parameter = raw[5:].encode()
    else:
        raise ValueError("Use hex: or text: prefix.")
    show_round_trip(message, key, "AES", "CTR", parameter)


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
