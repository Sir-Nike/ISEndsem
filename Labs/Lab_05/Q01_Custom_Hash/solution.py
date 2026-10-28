# Lab 5 Q1: Custom 32-bit string hash
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


def custom_hash(text, trace=False):
    """Input: text and optional trace flag. Mix character values into a 32-bit running value.
    Output: integer hash. custom_hash('hello') computes the hash; trace=True prints each step.
    """
    value = 5381
    for character in text:
        value = (((value << 5) + value) + ord(character)) & 0xFFFFFFFF
        if trace:
            print(repr(character), "code:", ord(character), "running hash:", value)
    return value


def exercise():
    """Input: a string. Print each hash update and compare with a changed string.
    Output: decimal/hex hash and modified-input hash; collisions remain possible.
    """
    text = ask_text("Text", "Information Security")
    value = custom_hash(text, True)
    print("Final decimal:", value, "Hex:", f"{value:08x}")
    print("Hash after adding !:", custom_hash(text + "!"))


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
