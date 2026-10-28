# Lab 1 Q5: Known-plaintext attack
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


def recover_shift(plaintext, ciphertext):
    """Input: known matching plaintext/ciphertext. Infer and validate the Caesar shift.
    Output: integer key 0-25. Use recover_shift('YES','CIW') to obtain 4.
    """
    plain, cipher = letters(plaintext), letters(ciphertext)
    if not plain or len(plain) != len(cipher):
        raise ValueError("Known texts must be nonempty and equal length.")
    shifts = {(ord(b) - ord(a)) % 26 for a, b in zip(plain, cipher)}
    if len(shifts) != 1:
        raise ValueError("These texts are inconsistent with a single shift.")
    return shifts.pop()


def exercise():
    """Input: known pair and target ciphertext. Recover the key and read the target.
    Output: attack type, shift and target plaintext. Defaults recover TREASURE.
    """
    plain = ask_text("Known plaintext", "YES")
    cipher = ask_text("Known ciphertext", "CIW")
    target = ask_text("Target ciphertext", "XVIEWYWI")
    key = recover_shift(plain, cipher)
    print("Known-plaintext attack. Key:", key, "Plaintext:", affine(target, 1, key, True))


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
