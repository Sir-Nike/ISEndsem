# Lab 7 additional 1a: ElGamal homomorphic multiplication
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


from Crypto.Util.number import getPrime, isPrime


def elgamal_keys(bits=256):
    """Input: demonstration modulus bit size. Generate safe prime p=2q+1 and subgroup generator.
    Output: (public dictionary p,g,y; private x). Use 2048+ bits for serious parameters.
    """
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            break
    g = 4
    x = secrets.randbelow(q - 1) + 1
    return {"p": p, "g": g, "y": pow(g, x, p)}, x


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


def elgamal_product(public, ciphertexts):
    """Input: ElGamal public parameters and ciphertext pairs. Multiply components modulo p.
    Output: ciphertext pair for the product of messages. Does not use the private exponent.
    """
    a, b = 1, 1
    for first, second in ciphertexts:
        a = a * first % public["p"]
        b = b * second % public["p"]
    return a, b


def exercise():
    """Input: two positive integers. Encrypt, homomorphically multiply and decrypt once.
    Output: public key, ciphertexts, encrypted product and verified plaintext product modulo p.
    """
    public, private = elgamal_keys(256)
    a = ask_int("First integer", 7, 1, public["p"] - 1)
    b = ask_int("Second integer", 3, 1, public["p"] - 1)
    first = elgamal_encrypt(public, a)
    second = elgamal_encrypt(public, b)
    product = elgamal_product(public, [first, second])
    result = elgamal_decrypt(public, private, product)
    print("Public:", public, "Ciphertexts:", first, second, "Encrypted product:", product)
    print(
        "Decrypted:",
        result,
        "Expected:",
        a * b % public["p"],
        "Verified:",
        result == a * b % public["p"],
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
