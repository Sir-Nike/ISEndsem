# Lab 1 additional Q2: Chosen-plaintext transposition attack
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


def infer_permutation(plain, cipher):
    """Input: equal-length texts with distinct symbols. Recover output-to-input positions.
    Output: 1-based permutation list. Reject inconsistent counts or repeated input symbols.
    """
    if sorted(plain) != sorted(cipher):
        raise ValueError("Not a pure transposition: input/output character counts differ.")
    if len(set(plain)) != len(plain):
        raise ValueError("Use distinct input symbols for an unambiguous mapping.")
    return [plain.index(c) + 1 for c in cipher]


def exercise():
    """Input: chosen plaintext and observed output. Identify attack and check the mapping.
    Output: a permutation if valid, or a clear explanation of the manual's inconsistency.
    """
    plain = ask_text("Chosen plaintext", "abcdefghi").upper()
    cipher = ask_text("Observed output", "CABDEHFGL").upper()
    print("Attack: chosen plaintext. Observed input length:", len(plain))
    try:
        print("Candidate full-block key:", infer_permutation(plain, cipher))
    except ValueError as error:
        print(error)
    print(
        "Corrected illustration ABCDEFGHI -> CABDEHFGI:",
        infer_permutation("ABCDEFGHI", "CABDEHFGI"),
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
