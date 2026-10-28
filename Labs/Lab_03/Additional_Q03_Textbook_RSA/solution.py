# Lab 3 additional Q3: Textbook RSA with small parameters
# Educational lab exercise. No user-defined classes are used.



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


def textbook_encrypt(data, n, e):
    """Input: plaintext bytes, modulus and public exponent. Encrypt each byte separately.
    Output: list of ciphertext integers. Modulus must exceed all byte values.
    """
    if n <= 255:
        raise ValueError("Modulus must exceed 255 for this byte encoding.")
    return [pow(value, e, n) for value in data]


def textbook_decrypt(ciphertext, n, d):
    """Input: ciphertext integer list, modulus and private exponent. Decrypt each integer.
    Output: recovered bytes; invalid/inconsistent key values may fail byte conversion.
    """
    return bytes(pow(value, d, n) for value in ciphertext)


def exercise():
    """Input: message and numeric RSA parameters. Show a small textbook-RSA example.
    Output: ciphertext list and recovered text, with a correctness check.
    """
    text = ask_text("Message", "Cryptographic Protocols")
    n = ask_int("n", 323, 256)
    e = ask_int("e", 5, 2)
    d = ask_int("d", 173, 2)
    ciphertext = textbook_encrypt(text.encode(), n, e)
    recovered = textbook_decrypt(ciphertext, n, d)
    print(
        "Ciphertext:",
        ciphertext,
        "Recovered:",
        recovered.decode(),
        "Verified:",
        recovered == text.encode(),
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
