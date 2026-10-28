# Lab 4 additional Q2: Attack weak RSA primes
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


def factor_small_modulus(n, limit=1000000):
    """Input: RSA modulus and trial-division bound. Search for a small factor.
    Output: (p,q), or ValueError when no factor is found within this educational bound.
    """
    if n % 2 == 0:
        return 2, n // 2
    for candidate in range(3, min(math.isqrt(n), limit) + 1, 2):
        if n % candidate == 0:
            return candidate, n // candidate
    raise ValueError("No small factor found. This is not a general attack on strong RSA.")


def attack_rsa(n, e, ciphertext):
    """Input: public n/e and ciphertext integer. Factor weak n and reconstruct the private exponent.
    Output: recovered d, decrypted integer and factors. Use only deliberately weak examples.
    """
    p, q = factor_small_modulus(n)
    if p == q or not isPrime(p) or not isPrime(q):
        raise ValueError("Demo expects two distinct prime factors.")
    d = pow(e, -1, (p - 1) * (q - 1))
    return d, pow(ciphertext, d, n), (p, q)


def exercise():
    """Input: weak primes and a message integer. Simulate interception and factor the public modulus.
    Output: recovered factors/private exponent, plaintext and suggested key-generation fixes.
    """
    p = ask_int("Small prime p", 1009, 3, 1000000)
    q = ask_int("Small prime q", 1013, 3, 1000000)
    if p == q or not isPrime(p) or not isPrime(q):
        raise ValueError("Use distinct primes.")
    n = p * q
    e = 65537
    if math.gcd(e, (p - 1) * (q - 1)) != 1:
        raise ValueError("Choose different primes for e=65537.")
    message = ask_int("Message integer", 123, 0, n - 1)
    ciphertext = pow(message, e, n)
    d, recovered, factors = attack_rsa(n, e, ciphertext)
    print(
        "Intercepted n,e,c:",
        n,
        e,
        ciphertext,
        "Recovered p,q:",
        factors,
        "d:",
        d,
        "Message:",
        recovered,
    )
    print("Verified:", recovered == message)
    print(
        "Mitigation: library-generated RSA-2048+ keys, cryptographic randomness, distinct independent primes, protect private keys, OAEP for encryption."
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
