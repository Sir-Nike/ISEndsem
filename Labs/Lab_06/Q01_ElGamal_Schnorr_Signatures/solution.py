# Lab 6 Q1: ElGamal and Schnorr signatures
# Educational lab exercise. No user-defined classes are used.

import math
import secrets
import hashlib


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


def signature_group(bits=256):
    """Input: safe-prime demonstration bit size. Generate p=2q+1, a full generator and subgroup generator.
    Output: (p,q,g,h) with g order 2q and h=g^2 order q. Used for ElGamal and Schnorr.
    """
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            break
    g = 2
    while pow(g, 2, p) == 1 or pow(g, q, p) == 1:
        g += 1
    return p, q, g, pow(g, 2, p)


def elgamal_sign(message, p, g, private):
    """Input: message bytes, prime p, full generator g and private exponent. Sign SHA-256 digest.
    Output: (r,s) signature. Fresh nonce k must be invertible modulo p-1 and never reused.
    """
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((digest - private * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s


def elgamal_verify(message, signature, p, g, public):
    """Input: message bytes, (r,s), parameters and public y=g^private. Check ElGamal equation.
    Output: boolean. Use elgamal_verify(data, signature, p, g, y).
    """
    r, s = signature
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return pow(g, digest, p) == (pow(public, r, p) * pow(r, s, p)) % p


def schnorr_challenge(commitment, message, q):
    """Input: integer commitment, message bytes and subgroup order. Hash both with unambiguous framing.
    Output: challenge integer modulo q. Used identically by signer and verifier.
    """
    encoded = commitment.to_bytes((commitment.bit_length() + 7) // 8 or 1, "big")
    return (
        int.from_bytes(
            hashlib.sha256(len(encoded).to_bytes(4, "big") + encoded + message).digest(), "big"
        )
        % q
    )


def schnorr_sign(message, p, q, h, private):
    """Input: message and Schnorr subgroup/private key. Commit with a fresh nonce and answer challenge.
    Output: (challenge,response). response=nonce+challenge*private modulo q.
    """
    nonce = secrets.randbelow(q - 1) + 1
    commitment = pow(h, nonce, p)
    challenge = schnorr_challenge(commitment, message, q)
    return challenge, (nonce + challenge * private) % q


def schnorr_verify(message, signature, p, q, h, public):
    """Input: message, signature, subgroup and public y=h^private. Rebuild the commitment.
    Output: boolean comparing the recomputed challenge against the signature challenge.
    """
    challenge, response = signature
    if not (0 <= challenge < q and 0 <= response < q):
        return False
    commitment = (pow(h, response, p) * pow(pow(public, challenge, p), -1, p)) % p
    return challenge == schnorr_challenge(commitment, message, q)


def exercise():
    """Input: message and demonstration bit size. Sign and verify using ElGamal and Schnorr.
    Output: parameters, signatures, valid checks and rejection of modified messages.
    """
    message = ask_text("Message", "A digitally signed document").encode()
    bits = ask_int("Demo safe-prime bits", 256, 64, 2048)
    p, q, g, h = signature_group(bits)
    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)
    signature = elgamal_sign(message, p, g, x)
    print("ElGamal public:", {"p": p, "g": g, "y": y}, "Signature:", signature)
    print(
        "Valid:",
        elgamal_verify(message, signature, p, g, y),
        "Tampered:",
        elgamal_verify(message + b"!", signature, p, g, y),
    )
    sx = secrets.randbelow(q - 1) + 1
    sy = pow(h, sx, p)
    ss = schnorr_sign(message, p, q, h, sx)
    print("Schnorr public:", {"p": p, "q": q, "h": h, "y": sy}, "Signature:", ss)
    print(
        "Valid:",
        schnorr_verify(message, ss, p, q, h, sy),
        "Tampered:",
        schnorr_verify(message + b"!", ss, p, q, h, sy),
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
