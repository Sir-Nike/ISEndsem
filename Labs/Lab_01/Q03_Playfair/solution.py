# Lab 1 Q3: Playfair cipher
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


def make_square(keyword):
    """Input: keyword. Build a unique 25-letter square with I/J merged.
    Output: a string in row-major order. Use make_square('GUIDANCE').
    """
    return "".join(
        dict.fromkeys((letters(keyword) + "ABCDEFGHIKLMNOPQRSTUVWXYZ").replace("J", "I"))
    )


def prepare_pairs(text):
    """Input: plaintext. Normalize, merge J/I and insert X (or Q after X) as filler.
    Output: even-length prepared text. Use before Playfair encryption.
    """
    text = letters(text).replace("J", "I")
    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 == len(text) or text[i + 1] == a:
            b = "Q" if a == "X" else "X"
            i += 1
        else:
            b = text[i + 1]
            i += 2
        result += a + b
    return result


def playfair(text, square, decrypt=False):
    """Input: text, 25-letter square and direction. Apply row/column/rectangle rules.
    Output: transformed pairs. Decryption preserves fillers because removal is ambiguous.
    """
    text = letters(text).replace("J", "I") if decrypt else prepare_pairs(text)
    if len(text) % 2:
        raise ValueError("Ciphertext must contain complete pairs.")
    output = ""
    step = -1 if decrypt else 1
    for i in range(0, len(text), 2):
        r1, c1 = divmod(square.index(text[i]), 5)
        r2, c2 = divmod(square.index(text[i + 1]), 5)
        if r1 == r2:
            c1, c2 = (c1 + step) % 5, (c2 + step) % 5
        elif c1 == c2:
            r1, r2 = (r1 + step) % 5, (r2 + step) % 5
        else:
            c1, c2 = c2, c1
        output += square[r1 * 5 + c1] + square[r2 * 5 + c2]
    return output


def exercise():
    """Input: message and keyword. Build the square and demonstrate encryption/decryption.
    Output: square, prepared text, ciphertext and filler-preserving plaintext.
    """
    text = ask_text("Message", "The key is hidden under the door pad")
    square = make_square(ask_text("Keyword", "GUIDANCE"))
    for i in range(0, 25, 5):
        print(square[i : i + 5])
    encrypted = playfair(text, square)
    print(
        "Prepared:",
        prepare_pairs(text),
        "Ciphertext:",
        encrypted,
        "Recovered:",
        playfair(encrypted, square, True),
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
