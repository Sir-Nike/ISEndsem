# Lab 7 Q2: RSA homomorphic multiplication
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


from Crypto.Util.number import isPrime


def raw_rsa_keys(p, q, e):
    """Input: distinct primes p/q and exponent coprime to phi. Compute textbook RSA parameters.
    Output: n,e,d tuple. Use only in the arithmetic demonstration, not for secure messaging.
    """
    if p == q or not isPrime(p) or not isPrime(q):
        raise ValueError("p/q must be distinct primes.")
    phi = (p - 1) * (q - 1)
    if not 1 < e < phi or math.gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi and in 2..phi-1.")
    return p * q, e, pow(e, -1, phi)


def multiply_encrypted(c1, c2, n):
    """Input: two raw RSA ciphertext integers and modulus. Multiply only ciphertext values.
    Output: ciphertext of the product modulo n. A private key is not needed here.
    """
    return c1 * c2 % n


def exercise():
    """Input: toy primes, exponent and two message integers. Demonstrate raw RSA multiplication.
    Output: ciphertexts, encrypted product, decrypted product and equality modulo n.
    """
    p = ask_int("Prime p", 61, 3)
    q = ask_int("Prime q", 53, 3)
    e = ask_int("Public exponent", 17, 2)
    n, e, d = raw_rsa_keys(p, q, e)
    a = ask_int("First integer", 7, 0, n - 1)
    b = ask_int("Second integer", 3, 0, n - 1)
    c1 = pow(a, e, n)
    c2 = pow(b, e, n)
    combined = multiply_encrypted(c1, c2, n)
    result = pow(combined, d, n)
    print("n:", n, "Ciphertexts:", c1, c2, "Encrypted product:", combined)
    print("Recovered:", result, "Expected modulo n:", a * b % n, "Verified:", result == a * b % n)


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
