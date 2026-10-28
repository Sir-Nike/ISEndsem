# Lab 6 Q3: Client/server signature and DH authentication
# Educational lab exercise. No user-defined classes are used.

import json
import secrets
import hashlib
from pathlib import Path


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


from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


from Crypto.Signature import pkcs1_15


def verify_message(public_key, message, signature):
    """Input: RSA public key, message bytes and signature bytes. Verify the SHA-256 signature.
    Output: True for a valid signature, False for altered message/signature or wrong key.
    """
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


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


def schnorr_verify(message, signature, p, q, h, public):
    """Input: message, signature, subgroup and public y=h^private. Rebuild the commitment.
    Output: boolean comparing the recomputed challenge against the signature challenge.
    """
    challenge, response = signature
    if not (0 <= challenge < q and 0 <= response < q):
        return False
    commitment = (pow(h, response, p) * pow(pow(public, challenge, p), -1, p)) % p
    return challenge == schnorr_challenge(commitment, message, q)


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


import socket
import struct


def receive_exact(connection, count):
    """Input: connected socket and required byte count. Read until all bytes arrive.
    Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.
    """
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ValueError("Connection closed before a complete message arrived.")
        data.extend(part)
    return bytes(data)


def send_json(connection, record):
    """Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
    Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.
    """
    data = json.dumps(record).encode()
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Frame exceeds 2 MB teaching limit.")
    connection.sendall(struct.pack("!I", len(data)) + data)


def receive_json(connection):
    """Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
    Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.
    """
    size = struct.unpack("!I", receive_exact(connection, 4))[0]
    if size > 2 * 1024 * 1024:
        raise ValueError("Incoming frame too large.")
    return json.loads(receive_exact(connection, size))


def check_signed_request(request, identity, scheme, shared_key=None):
    """Input: request, pretrusted client identity, chosen scheme and optional DH-derived key.
    Output: (valid original, valid changed message). Dispatch only to the specified verifier.
    """
    import hmac

    data = bytes.fromhex(request["message"])
    if scheme == "RSA":
        public = RSA.import_key(identity["rsa"])
        signature = bytes.fromhex(request["signature"])
        return verify_message(public, data, signature), verify_message(
            public, data + b"!", signature
        )
    if scheme == "ElGamal":
        signature = request["signature"]
        p, g, y = identity["p"], identity["g"], identity["y"]
        return elgamal_verify(data, signature, p, g, y), elgamal_verify(
            data + b"!", signature, p, g, y
        )
    if scheme == "Schnorr":
        signature = request["signature"]
        p, q, h, y = identity["p"], identity["q"], identity["h"], identity["sy"]
        return schnorr_verify(data, signature, p, q, h, y), schnorr_verify(
            data + b"!", signature, p, q, h, y
        )
    if scheme == "DH-HMAC":
        tag = request["tag"]
        good = hmac.new(shared_key, data, hashlib.sha256).hexdigest()
        changed = hmac.new(shared_key, data + b"!", hashlib.sha256).hexdigest()
        return hmac.compare_digest(good, tag), hmac.compare_digest(changed, tag)
    raise ValueError("Unknown algorithm.")


def exercise():
    """Input: server address, trusted client public JSON path and connection count.
    Output: verifies RSA/ElGamal/Schnorr signatures or DH-HMAC; sends valid/tampered checks.
    """
    host = ask_text("Bind host", "127.0.0.1")
    port = ask_int("Port", 5063, 1024, 65535)
    path = Path(
        ask_text(
            "Trusted client public identity path",
            str(Path(__file__).resolve().parent / "client_public.json"),
        )
    )
    identity = json.loads(path.read_text())
    count = ask_int("Connections before returning", 1, 1, 100)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        listener.settimeout(60)
        print("Listening", host, port, flush=True)
        for _ in range(count):
            connection, address = listener.accept()
            with connection:
                connection.settimeout(15)
                try:
                    scheme = receive_json(connection)["scheme"]
                    if scheme not in ("RSA", "ElGamal", "Schnorr", "DH-HMAC"):
                        raise ValueError("Unknown scheme.")
                    shared = None
                    if scheme == "DH-HMAC":
                        private, public = dh_keypair()
                        shared = dh_shared(private, identity["dh_public"])
                        send_json(connection, {"dh_public": public})
                    else:
                        send_json(connection, {"ready": True})
                    request = receive_json(connection)
                    valid, changed = check_signed_request(request, identity, scheme, shared)
                    send_json(
                        connection, {"scheme": scheme, "valid": valid, "tampered_valid": changed}
                    )
                    print(scheme, "Valid:", valid, "Tampered valid:", changed)
                except (ValueError, KeyError, TypeError, OSError) as error:
                    print("Rejected client:", error)


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
