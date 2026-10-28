# Lab 2 Q3: DES versus AES-256 timing
# Educational lab exercise. No user-defined classes are used.

import time


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


from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


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


def benchmark(message, key, algorithm, mode, repeats):
    """Input: text, key, algorithm, mode and positive repeat count. Time complete operations.
    Output: average encryption and decryption microseconds; setup and padding are included.
    """
    if repeats < 1:
        raise ValueError("Repeat count must be positive.")
    data = message.encode()
    start = time.perf_counter()
    for _ in range(repeats):
        iv, ciphertext = encrypt_bytes(data, key, algorithm, mode)
    encryption = (time.perf_counter() - start) / repeats * 1e6
    start = time.perf_counter()
    for _ in range(repeats):
        plain = decrypt_bytes(iv, ciphertext, key, algorithm, mode)
    decryption = (time.perf_counter() - start) / repeats * 1e6
    assert plain == data
    return encryption, decryption


def exercise():
    """Input: message and repeat count. Benchmark DES and AES-256 using random valid keys.
    Output: average microseconds for encryption and decryption with a verified round trip.
    """
    message = ask_text("Message", "Performance Testing of Encryption Algorithms")
    repeats = ask_int("Repetitions", 100, 1, 100000)
    for algorithm, size in [("DES", 8), ("AES", 32)]:
        enc, dec = benchmark(message, get_random_bytes(size), algorithm, "CBC", repeats)
        print(algorithm, size * 8, "bits: encrypt us", round(enc, 3), "decrypt us", round(dec, 3))


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
