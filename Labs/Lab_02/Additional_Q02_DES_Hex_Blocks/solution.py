# Lab 2 additional Q2: DES hexadecimal data
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


def exercise():
    """Input: DES hex key and two hex plaintext strings. Encrypt each independently.
    Output: IV, ciphertext, recovered hex and decoded text for each supplied message.
    """
    key = parse_key(ask_text("Key", "hex:A1B2C3D4E5F60708"), "DES")
    examples = [
        "54686973206973206120636f6e666964656e7469616c206d657373616765",
        "416e64207468697320697320746865207365636f6e6420626c6f636b",
    ]
    for i, default in enumerate(examples, 1):
        data = bytes.fromhex(ask_text(f"Hex message {i}", default))
        iv, ciphertext = encrypt_bytes(data, key, "DES", "CBC")
        recovered = decrypt_bytes(iv, ciphertext, key, "DES", "CBC")
        print("Message", i, "IV:", iv.hex(), "Ciphertext:", ciphertext.hex())
        print(
            "Recovered hex:",
            recovered.hex(),
            "Text:",
            recovered.decode(errors="replace"),
            "Verified:",
            recovered == data,
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
