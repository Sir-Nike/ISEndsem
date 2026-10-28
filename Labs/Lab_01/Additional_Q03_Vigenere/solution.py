# Lab 1 additional Q3: Vigenere with HEALTH
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


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


def exercise():
    """Input: message and keyword. Demonstrate Vigenere encryption and decryption.
    Output: ciphertext and recovered letters. Defaults use the additional exercise values.
    """
    text = ask_text("Message", "Life is full of surprises")
    key = ask_text("Keyword", "HEALTH")
    ciphertext = vigenere(text, key)
    print("Ciphertext:", ciphertext, "Recovered:", vigenere(ciphertext, key, True))


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
