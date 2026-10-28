# Lab 3 Q5: Diffie-Hellman peer key exchange
# Educational lab exercise. No user-defined classes are used.

import time
import secrets
import hashlib

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


def exercise():
    """Input: none. Generate two peers' keys and derive their shared AES key.
    Output: public values, timing measurements and equality of the derived keys.
    """
    start = time.perf_counter()
    a, A = dh_keypair()
    b, B = dh_keypair()
    generation = time.perf_counter() - start
    start = time.perf_counter()
    alice = dh_shared(a, B)
    bob = dh_shared(b, A)
    exchange = time.perf_counter() - start
    print("Alice public:", A, "Bob public:", B)
    print("Generation seconds:", generation, "Exchange seconds:", exchange)
    print("Demo shared key:", alice.hex(), "Both peers agree:", alice == bob)
    assert alice == bob


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
