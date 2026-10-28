# Lab 1 additional Q1: Caesar brute force
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


def shift_preserving_punctuation(text, key):
    """Input: ciphertext and key. Subtract the key from letters and retain other symbols.
    Output: candidate plaintext. Call once for each key to brute-force Caesar.
    """
    return "".join(
        chr(65 + (ord(c) - 65 - key) % 26) if "A" <= c <= "Z" else c for c in text.upper()
    )


def exercise():
    """Input: ciphertext and birthday hint. Print every possible Caesar decryption.
    Output: 26 candidates, with keys nearest the hint first; inspect readable candidates.
    """
    text = ask_text("Ciphertext", "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY")
    hint = ask_int("Birthday key hint", 13, 0, 25)
    for key in sorted(range(26), key=lambda k: min((k - hint) % 26, (hint - k) % 26)):
        print(f"Key {key:2}: {shift_preserving_punctuation(text,key)}")


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
