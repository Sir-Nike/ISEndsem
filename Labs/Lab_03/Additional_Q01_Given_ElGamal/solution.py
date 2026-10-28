# Lab 3 additional Q1: ElGamal with supplied parameters
# Educational lab exercise. No user-defined classes are used.

import secrets


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


from Crypto.Util.number import isPrime


def elgamal_encrypt(public, message):
    """Input: ElGamal public parameters and integer 1<=message<p. Randomize and encrypt.
    Output: pair (g^k mod p, message*y^k mod p). Use fresh k for every encryption.
    """
    p, g, y = public["p"], public["g"], public["y"]
    if not 1 <= message < p:
        raise ValueError("ElGamal message must lie in 1..p-1.")
    k = secrets.randbelow(p - 2) + 1
    return pow(g, k, p), (message * pow(y, k, p)) % p


def elgamal_decrypt(public, private, ciphertext):
    """Input: public parameters, private exponent and ciphertext pair. Remove the shared mask.
    Output: original integer. Multiply c2 by the modular inverse of c1^private.
    """
    a, b = ciphertext
    return b * pow(pow(a, private, public["p"]), -1, public["p"]) % public["p"]


def elgamal_text_encrypt(public, text):
    """Input: public parameters with p>256 and text. Encrypt each UTF-8 byte plus one.
    Output: list of ciphertext pairs. Byte-wise encryption is simple but inefficient.
    """
    if public["p"] <= 256:
        raise ValueError("Modulus must exceed 256 for this encoding.")
    return [elgamal_encrypt(public, b + 1) for b in text.encode()]


def elgamal_text_decrypt(public, private, ciphertexts):
    """Input: ElGamal keys and list of encrypted byte pairs. Decrypt and undo the +1 mapping.
    Output: decoded UTF-8 string. Use with elgamal_text_encrypt.
    """
    return bytes(elgamal_decrypt(public, private, c) - 1 for c in ciphertexts).decode()


def exercise():
    """Input: message and supplied ElGamal parameters. Check key consistency and round-trip.
    Output: supplied/derived public values, ciphertexts and recovered message.
    """
    text = ask_text("Message", "Asymmetric Algorithms")
    p = ask_int("Prime p", 7919, 257)
    g = ask_int("Generator g", 2, 2, p - 2)
    h = ask_int("Supplied public h", 6465, 1, p - 1)
    x = ask_int("Private x", 2999, 1, p - 2)
    if not isPrime(p):
        raise ValueError("p must be prime.")
    derived = pow(g, x, p)
    if h != derived:
        print("Inconsistent supplied h:", h, "Using g^x mod p =", derived)
    public = {"p": p, "g": g, "y": derived}
    ciphertext = elgamal_text_encrypt(public, text)
    print("Ciphertext:", ciphertext, "Recovered:", elgamal_text_decrypt(public, x, ciphertext))


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
