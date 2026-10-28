# Lab 6 Q2: Diffie-Hellman with message authentication
# Educational lab exercise. No user-defined classes are used.

import secrets
import hashlib


def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


# RFC 3526 group 14: a fixed standard 2048-bit safe prime, generator 2.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2


def dh_keypair(p=DH_P, g=DH_G):
    """Input: prime and generator (standard defaults). Draw a random private exponent.
    Output: (private, public=g^private mod p). Only the public value is exchanged.
    """
    private = secrets.randbelow((p - 1) // 2 - 2) + 2
    return private, pow(g, private, p)


def dh_shared(private, peer_public, p=DH_P):
    """Input: own private exponent, peer public value and safe prime. Validate the peer.
    Output: SHA-256-derived 32-byte shared key. Both peers get the same key.
    """
    if not 2 <= peer_public <= p - 2 or pow(peer_public, (p - 1) // 2, p) != 1:
        raise ValueError("Invalid Diffie-Hellman public value.")
    secret = pow(peer_public, private, p)
    return hashlib.sha256(secret.to_bytes((p.bit_length() + 7) // 8, "big")).digest()


def make_mac(key, message):
    """Input: shared secret key bytes and message bytes. Compute HMAC-SHA256.
    Output: hexadecimal authentication tag. Both DH peers can create this tag.
    """
    import hmac

    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_mac(key, message, tag):
    """Input: shared key, message and supplied HMAC hex. Compare against recomputed HMAC.
    Output: boolean using a timing-safe comparison. Use with make_mac.
    """
    import hmac

    return hmac.compare_digest(make_mac(key, message), tag)


def exercise():
    """Input: message. Exchange DH values and authenticate the message with the shared key.
    Output: shared-key equality, HMAC and original/tampered verification checks.
    """
    message = ask_text("Message", "Authenticate this document").encode()
    a, A = dh_keypair()
    b, B = dh_keypair()
    alice = dh_shared(a, B)
    bob = dh_shared(b, A)
    tag = make_mac(alice, message)
    print("DH keys match:", alice == bob, "HMAC:", tag)
    print(
        "Valid:", verify_mac(bob, message, tag), "Tampered:", verify_mac(bob, message + b"!", tag)
    )
    print(
        "DH is key agreement. HMAC authenticates between peers; use RSA/ElGamal/Schnorr for a signature."
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
