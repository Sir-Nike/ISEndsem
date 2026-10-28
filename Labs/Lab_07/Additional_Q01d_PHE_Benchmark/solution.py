# Lab 7 additional 1d: Paillier and ElGamal benchmarking
# Educational lab exercise. No user-defined classes are used.

import math
import time
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
    """Input: modulus size and repetition count. Benchmark valid additive/multiplicative computations.
    Output: per-scheme keygen and average encryption, aggregation and aggregate-decryption times.
    """
    bits = ask_int("Demo modulus bits", 256, 128, 2048)
    repeats = ask_int("Repetitions", 10, 1, 1000)
    for scheme in ("Paillier", "ElGamal"):
        start = time.perf_counter()
        public, private = paillier_keys(bits) if scheme == "Paillier" else elgamal_keys(bits)
        generation = time.perf_counter() - start
        totals = [0.0, 0.0, 0.0]
        for _ in range(repeats):
            start = time.perf_counter()
            encrypted = [
                (
                    paillier_encrypt(public, value)
                    if scheme == "Paillier"
                    else elgamal_encrypt(public, value)
                )
                for value in (15, 25)
            ]
            totals[0] += time.perf_counter() - start
            start = time.perf_counter()
            if scheme == "Paillier":
                combined = encrypted_sum(public, encrypted)
            else:
                combined = (
                    encrypted[0][0] * encrypted[1][0] % public["p"],
                    encrypted[0][1] * encrypted[1][1] % public["p"],
                )
            totals[1] += time.perf_counter() - start
            start = time.perf_counter()
            result = (
                paillier_decrypt(public, private, combined)
                if scheme == "Paillier"
                else elgamal_decrypt(public, private, combined)
            )
            totals[2] += time.perf_counter() - start
            assert result == (40 if scheme == "Paillier" else 375)
        print(
            scheme,
            "keygen s:",
            generation,
            "mean seconds [encrypt pair, aggregate, decrypt]:",
            [v / repeats for v in totals],
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
