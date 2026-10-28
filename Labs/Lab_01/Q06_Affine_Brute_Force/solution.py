# Lab 1 Q6: Brute-force affine cipher
# Educational lab exercise. No user-defined classes are used.

import math


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


def affine(text, a, b, decrypt=False):
    """Input: text, multiplier a, shift b, and direction. Apply (a*x+b) modulo 26.
    Output: letters only. Set decrypt=True to use a's modular inverse and recover text.
    """
    if math.gcd(a, 26) != 1:
        raise ValueError("Multiplier must be coprime to 26: 1,3,5,7,9,11,15,17,19,21,23,25.")
    result = []
    for c in letters(text):
        x = ord(c) - 65
        y = (pow(a, -1, 26) * (x - b)) % 26 if decrypt else (a * x + b) % 26
        result.append(chr(65 + y))
    return "".join(result)


def find_keys(known_plain, known_cipher):
    """Input: known plaintext and ciphertext. Enumerate valid affine keys matching the clue.
    Output: list of (a,b) pairs. Use the pairs to decrypt a longer ciphertext.
    """
    if not letters(known_plain) or len(letters(known_plain)) != len(letters(known_cipher)):
        raise ValueError("Known pair must have matching nonzero lengths.")
    return [
        (a, b)
        for a in range(26)
        if math.gcd(a, 26) == 1
        for b in range(26)
        if affine(known_plain, a, b) == letters(known_cipher)
    ]


def exercise():
    """Input: ciphertext and known pair. Brute-force matching keys and print plaintexts.
    Output: each surviving affine key and its decryption.
    """
    ciphertext = ask_text("Ciphertext", "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS")
    known = ask_text("Known plaintext", "ab")
    encoded = ask_text("Known ciphertext", "GL")
    keys = find_keys(known, encoded)
    for a, b in keys:
        print("a,b:", a, b, "Plaintext:", affine(ciphertext, a, b, True))
    if not keys:
        print("No key matches the clue.")


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
