# Lab 1 Q2: Vigenere and autokey
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


def letters(text):
    """Input: any string. Keep only English A-Z letters and uppercase them.
    Output: normalized text. Use before a classical cipher; spaces are discarded.
    """
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def vigenere(text, keyword, decrypt=False):
    """Input: text and nonempty keyword. Add repeating key letters modulo 26.
    Output: encrypted or recovered letters. Set decrypt=True to subtract the key.
    """
    text, keyword = letters(text), letters(keyword)
    if not keyword:
        raise ValueError("Keyword must contain an English letter.")
    direction = -1 if decrypt else 1
    return "".join(
        chr(65 + (ord(c) - 65 + direction * (ord(keyword[i % len(keyword)]) - 65)) % 26)
        for i, c in enumerate(text)
    )


def autokey(text, first_key, decrypt=False):
    """Input: text and initial shift 0-25. Extend the key with plaintext letters.
    Output: encrypted/recovered text. Decryption feeds recovered letters back into the key.
    """
    if not 0 <= first_key < 26:
        raise ValueError("Initial key must be between 0 and 25.")
    key_stream = [first_key]
    result = []
    for i, c in enumerate(letters(text)):
        value = ord(c) - 65
        out = (value - key_stream[i]) % 26 if decrypt else (value + key_stream[i]) % 26
        result.append(chr(65 + out))
        key_stream.append(out if decrypt else value)
    return "".join(result)


def exercise():
    """Input: message, keyword and initial autokey shift. Run both round trips.
    Output: ciphertexts and recovered plaintext. Select 1 in the menu.
    """
    text = ask_text("Message", "the house is being sold tonight")
    key = ask_text("Vigenere keyword", "dollars")
    first = ask_int("Autokey initial shift", 7, 0, 25)
    encrypted = vigenere(text, key)
    print("Vigenere:", encrypted, "Recovered:", vigenere(encrypted, key, True))
    encrypted = autokey(text, first)
    print("Autokey:", encrypted, "Recovered:", autokey(encrypted, first, True))


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
