# Lab 7 additional 1c: Custodian threshold for final decryption
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


def split_secret(secret, threshold, count, prime):
    """Input: secret integer, required share count, total shares and prime field > secret.
    Output: list of (x,y) Shamir shares. Any threshold shares reconstruct the secret.
    """
    if not 2 <= threshold <= count < prime or not 0 <= secret < prime:
        raise ValueError("Invalid share parameters.")
    coefficients = [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]
    # Keep the leading coefficient nonzero so the polynomial really has the required degree.
    coefficients[-1] = secrets.randbelow(prime - 1) + 1
    shares = []
    for x in range(1, count + 1):
        y = (
            sum(coefficient * pow(x, i, prime) for i, coefficient in enumerate(coefficients))
            % prime
        )
        shares.append((x, y))
    return shares


def reconstruct_secret(shares, prime, threshold):
    """Input: distinct Shamir shares, prime and required count. Interpolate polynomial at zero.
    Output: secret integer. Reject too few shares or repeated x coordinates.
    """
    if len(shares) < threshold:
        raise ValueError("Not enough custodians: threshold not reached.")
    if len({x for x, y in shares}) != len(shares):
        raise ValueError("Repeated share numbers.")
    result = 0
    for i, (x, y) in enumerate(shares):
        numerator = denominator = 1
        for j, (other, _) in enumerate(shares):
            if i != j:
                numerator = numerator * (-other) % prime
                denominator = denominator * (x - other) % prime
        result = (result + y * numerator * pow(denominator, -1, prime)) % prime
    return result


def threshold_controlled_decrypt(public, ciphertext, shares, prime, threshold):
    """Input: final aggregate ciphertext, public key and enough custodian shares of lambda.
    Output: aggregate integer. Reconstruct lambda locally and derive mu; never decrypt inputs here.
    """
    lam = reconstruct_secret(shares, prime, threshold)
    private = {"lambda": lam, "mu": pow(lam, -1, public["n"])}
    return paillier_decrypt(public, private, ciphertext)


def exercise():
    """Input: values, custodian count and threshold. Demonstrate threshold-controlled final decryption.
    Output: share distribution, denial below threshold and successful final-total recovery.
    """
    values = [int(x) for x in ask_text("Amounts", "15,25,35").split(",")]
    count = ask_int("Custodians", 3, 2, 10)
    threshold = ask_int("Required custodians", 2, 2, count)
    public, private = paillier_keys(512)
    prime = getPrime(public["n"].bit_length() + 16)
    shares = split_secret(private["lambda"], threshold, count, prime)
    # In a real service, deliver each share privately to a different custodian.
    print("Shares created for custodian numbers:", [x for x, y in shares])
    aggregate = encrypted_sum(public, [paillier_encrypt(public, value) for value in values])
    del private
    try:
        threshold_controlled_decrypt(public, aggregate, shares[: threshold - 1], prime, threshold)
    except ValueError as error:
        print("Below threshold rejected:", error)
    result = threshold_controlled_decrypt(public, aggregate, shares[:threshold], prime, threshold)
    print(
        "Encrypted aggregate:",
        aggregate,
        "Decrypted final total:",
        result,
        "Verified:",
        result == sum(values) % public["n"],
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
