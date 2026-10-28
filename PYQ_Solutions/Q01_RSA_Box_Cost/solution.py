import math
from Crypto.Util.number import isPrime


def ask_text(label, default=None):
    """Input: prompt and optional default. Read terminal text; Enter accepts a supplied default.
    Output: nonempty string. Use ask_text('Patient ID') when a value must be entered.
    """
    shown = f" [{default}]" if default is not None else ""
    value = input(label + shown + ": ").strip()
    if not value and default is not None:
        return str(default)
    if not value:
        raise ValueError(label + " cannot be empty.")
    return value


def ask_int(label, default=None, minimum=None, maximum=None):
    """Input: prompt, optional default and inclusive bounds. Read and validate an integer.
    Output: integer, or ValueError. Use for menu parameters, counts and cryptographic sizes.
    """
    value = int(ask_text(label, default))
    if minimum is not None and value < minimum:
        raise ValueError(label + " is too small.")
    if maximum is not None and value > maximum:
        raise ValueError(label + " is too large.")
    return value


def configure_rsa():
    """Input: choice of supplied n/e/d or supplied p/q/e. Read every RSA value from the user.
    Output: n/e/d dictionary after arithmetic checks. No exam parameters are hardcoded.
    """
    choice = ask_text("1 Enter p,q,e; 2 Enter n,e,d")
    if choice == "1":
        p = ask_int("Prime p", minimum=3)
        q = ask_int("Prime q", minimum=3)
        if p == q or not isPrime(p) or not isPrime(q):
            raise ValueError("p and q must be distinct primes.")
        n = p * q
        phi = (p - 1) * (q - 1)
        e = ask_int("Public exponent e", minimum=2, maximum=phi - 1)
        if math.gcd(e, phi) != 1:
            raise ValueError("e must be coprime to phi(n).")
        d = pow(e, -1, phi)
    elif choice == "2":
        n = ask_int("Modulus n", minimum=4)
        e = ask_int("Public exponent e", minimum=2)
        d = ask_int("Private exponent d", minimum=2)
        for value in (1, 2, 3, n - 1):
            if value < n and pow(pow(value, e, n), d, n) != value:
                raise ValueError("Supplied RSA parameters fail a round-trip check.")
    else:
        raise ValueError("Choose 1 or 2.")
    print("Configured n:", n, "e:", e, "d:", d)
    return {"n": n, "e": e, "d": d}


def encrypt_inputs(number_of_boxes, cost_per_box, public):
    """Input: two integers and public n/e dictionary. Check both values lie in 1..n-1 and encrypt separately.
    Output: two raw RSA ciphertext integers. The multiplication function receives only these ciphertexts.
    """
    n = public["n"]
    if not 1 <= number_of_boxes < n or not 1 <= cost_per_box < n:
        raise ValueError("Both inputs must lie between 1 and n-1.")
    return pow(number_of_boxes, public["e"], n), pow(cost_per_box, public["e"], n)


def multiply_ciphertexts(first, second, n):
    """Input: two ciphertexts and public modulus only. Multiply them modulo n without decryption.
    Output: RSA ciphertext of the plaintext product modulo n. No original inputs or private key are needed.
    """
    if not 0 <= first < n or not 0 <= second < n:
        raise ValueError("Ciphertexts outside modulus range.")
    return first * second % n


def decrypt_and_verify(ciphertext, parameters, number_of_boxes, cost_per_box):
    """Input: product ciphertext, RSA parameters and original inputs for the final comparison only.
    Output: recovered product integer and verification boolean; print modular and ordinary products.
    """
    result = pow(ciphertext, parameters["d"], parameters["n"])
    expected = number_of_boxes * cost_per_box % parameters["n"]
    verified = result == expected
    print("Ordinary product:", number_of_boxes * cost_per_box)
    print("Expected product modulo n:", expected, "Decrypted product:", result)
    print("Verified" if verified else "Verification FAILED")
    if number_of_boxes * cost_per_box >= parameters["n"]:
        print(
            "The ordinary product wraps modulo n; use a larger modulus if the exact total is required."
        )
    return result, verified


def main():
    """Input: menu choices and user-supplied RSA parameters/box values. Enforce the operation order.
    Output: input ciphertexts, ciphertext-only product and final verification. Run python solution.py.
    """
    parameters = None
    inputs = None
    ciphertexts = None
    product = None
    while True:
        print(
            "\n1 Configure RSA  2 Input and encrypt boxes/cost  3 Multiply ciphertexts  4 Decrypt and verify  0 Exit"
        )
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice == "1":
                parameters = configure_rsa()
                inputs = ciphertexts = product = None
            elif choice == "2":
                if parameters is None:
                    raise ValueError("Configure RSA first.")
                boxes = ask_int("Number of boxes", minimum=1, maximum=parameters["n"] - 1)
                cost = ask_int(
                    "Cost per box (integer units)", minimum=1, maximum=parameters["n"] - 1
                )
                ciphertexts = encrypt_inputs(boxes, cost, parameters)
                inputs = (boxes, cost)
                product = None
                print("Encrypted boxes:", ciphertexts[0], "Encrypted cost:", ciphertexts[1])
            elif choice == "3":
                if ciphertexts is None:
                    raise ValueError("Encrypt the inputs first.")
                product = multiply_ciphertexts(*ciphertexts, parameters["n"])
                print("Encrypted product:", product)
            elif choice == "4":
                if product is None:
                    raise ValueError("Multiply the ciphertexts first.")
                decrypt_and_verify(product, parameters, *inputs)
            else:
                print("Choose a listed option.")
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            print("Rejected:", error)


if __name__ == "__main__":
    main()
