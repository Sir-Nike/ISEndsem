# Lab 1 Q4: Hill cipher
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


def inverse_matrix(key):
    """Input: four integers [a,b,c,d]. Invert the 2x2 matrix modulo 26.
    Output: four inverse entries. Raise ValueError when determinant is not invertible.
    """
    a, b, c, d = key
    determinant = (a * d - b * c) % 26
    inverse = pow(determinant, -1, 26)
    return [(inverse * d) % 26, (-inverse * b) % 26, (-inverse * c) % 26, (inverse * a) % 26]


def hill(text, key, decrypt=False):
    """Input: text, row-major 2x2 key and direction. Multiply column pairs modulo 26.
    Output: transformed letters. For decryption pass an even-length ciphertext.
    """
    inverse_matrix(key)
    key = inverse_matrix(key) if decrypt else key
    text = letters(text)
    if len(text) % 2:
        if decrypt:
            raise ValueError("Ciphertext length must be even.")
        text += "X"
    a, b, c, d = key
    result = ""
    for i in range(0, len(text), 2):
        x, y = ord(text[i]) - 65, ord(text[i + 1]) - 65
        result += chr(65 + (a * x + b * y) % 26) + chr(65 + (c * x + d * y) % 26)
    return result


def exercise():
    """Input: message and four space-separated matrix entries. Run the Hill round trip.
    Output: inverse matrix, encrypted letters, recovered letters including padding.
    """
    text = ask_text("Message", "We live in an insecure world")
    key = [int(x) for x in ask_text("Matrix entries a b c d", "3 3 2 7").split()]
    if len(key) != 4:
        raise ValueError("Enter four integers.")
    encrypted = hill(text, key)
    print(
        "Inverse:",
        inverse_matrix(key),
        "Ciphertext:",
        encrypted,
        "Recovered:",
        hill(encrypted, key, True),
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
