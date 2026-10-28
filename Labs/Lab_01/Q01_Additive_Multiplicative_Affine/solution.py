# Lab 1 Q1: Additive, multiplicative and affine ciphers
# Educational lab exercise. No user-defined classes are used.

import math


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


def exercise():
    """Input: message and three key values from prompts. Demonstrate all three ciphers.
    Output: ciphertexts, recovered messages and equality checks. Choose menu option 1.
    """
    text = ask_text("Message", "I am learning information security")
    shift = ask_int("Additive key", 20)
    multiplier = ask_int("Multiplicative/affine multiplier", 15)
    offset = ask_int("Affine shift", 20)
    for name, a, b in [
        ("Additive", 1, shift),
        ("Multiplicative", multiplier, 0),
        ("Affine", multiplier, offset),
    ]:
        ciphertext = affine(text, a, b)
        recovered = affine(ciphertext, a, b, True)
        print(
            name,
            "ciphertext:",
            ciphertext,
            "recovered:",
            recovered,
            "verified:",
            recovered == letters(text),
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
