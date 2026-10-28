# Lab 7 Q1: Paillier homomorphic addition
# Educational lab exercise. No user-defined classes are used.

import math
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


from Crypto.Util.number import getPrime


def paillier_keys(bits=512):
    """Input: desired modulus size. Generate p/q and compute Paillier parameters with g=n+1.
    Output: (public dictionary n/g, private dictionary lambda/mu). Keep private values secret.
    """
    if bits < 128:
        raise ValueError("Use at least 128 bits for this teaching exercise.")
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        lam = math.lcm(p - 1, q - 1)
        if math.gcd(lam, n) == 1:
            break
    return {"n": n, "g": n + 1}, {"lambda": lam, "mu": pow(lam, -1, n)}


def paillier_encrypt(public, message):
    """Input: public n/g and integer 0<=message<n. Choose fresh random r coprime to n.
    Output: ciphertext g^message * r^n modulo n^2. Same message encrypts differently each time.
    """
    n = public["n"]
    if not isinstance(message, int) or not 0 <= message < n:
        raise ValueError("Message must be an integer in 0..n-1.")
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return pow(public["g"], message, n * n) * pow(r, n, n * n) % (n * n)


def paillier_decrypt(public, private, ciphertext):
    """Input: matching public/private keys and valid ciphertext. Apply L(c^lambda)*mu modulo n.
    Output: plaintext integer modulo n. L(u) means (u-1)//n.
    """
    n = public["n"]
    if not 0 < ciphertext < n * n or math.gcd(ciphertext, n) != 1:
        raise ValueError("Invalid Paillier ciphertext.")
    u = pow(ciphertext, private["lambda"], n * n)
    return ((u - 1) // n) * private["mu"] % n


def encrypted_sum(public, ciphertexts):
    """Input: public key and iterable of Paillier ciphertexts. Multiply modulo n^2.
    Output: encryption of the sum modulo n. No individual plaintext or private key is needed.
    """
    n2 = public["n"] ** 2
    result = 1
    for ciphertext in ciphertexts:
        if not 0 < ciphertext < n2 or math.gcd(ciphertext, public["n"]) != 1:
            raise ValueError("Invalid ciphertext in sum.")
        result = result * ciphertext % n2
    return result


def exercise():
    """Input: two nonnegative integers and modulus size. Encrypt and add without individual decryption.
    Output: ciphertexts, encrypted sum, decrypted sum and modulo-n verification.
    """
    bits = ask_int("Demo modulus bits", 512, 128, 4096)
    public, private = paillier_keys(bits)
    a = ask_int("First integer", 15, 0, public["n"] - 1)
    b = ask_int("Second integer", 25, 0, public["n"] - 1)
    c1 = paillier_encrypt(public, a)
    c2 = paillier_encrypt(public, b)
    combined = encrypted_sum(public, [c1, c2])
    result = paillier_decrypt(public, private, combined)
    print("n:", public["n"], "Ciphertexts:", c1, c2, "Encrypted sum:", combined)
    print(
        "Decrypted sum:",
        result,
        "Expected modulo n:",
        (a + b) % public["n"],
        "Verified:",
        result == (a + b) % public["n"],
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
