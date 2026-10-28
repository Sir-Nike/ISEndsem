# Lab 6 Q3: Client/server signature and DH authentication - client

import json
import math
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
from Crypto.Util.number import getPrime, isPrime


from Crypto.Signature import pkcs1_15


def sign_message(private_key, message):
    """Input: RSA private key and message bytes. Hash with SHA-256 and sign with PKCS#1 v1.5.
    Output: signature bytes. Use verify_message with the corresponding public key.
    """
    return pkcs1_15.new(private_key).sign(SHA256.new(message))


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


def prepare_identity(folder):
    """Input: client directory. Generate/load RSA, ElGamal, Schnorr and DH private identity values.
    Output: private dictionary. Export only public values to client_public.json for server trust.
    """
    private_path = folder / "client_private.json"
    if private_path.exists():
        identity = json.loads(private_path.read_text())
    else:
        rsa = RSA.generate(2048)
        p, q, g, h = signature_group(256)
        x = secrets.randbelow(q - 1) + 1
        sx = secrets.randbelow(q - 1) + 1
        dh_private, dh_public = dh_keypair()
        identity = {
            "rsa_private": rsa.export_key().decode(),
            "p": p,
            "q": q,
            "g": g,
            "h": h,
            "x": x,
            "sx": sx,
            "y": pow(g, x, p),
            "sy": pow(h, sx, p),
            "dh_private": dh_private,
            "dh_public": dh_public,
        }
        private_path.write_text(json.dumps(identity, indent=2))
        private_path.chmod(0o600)
    public = {name: identity[name] for name in ("p", "q", "g", "h", "y", "sy", "dh_public")}
    public["rsa"] = RSA.import_key(identity["rsa_private"]).publickey().export_key().decode()
    (folder / "client_public.json").write_text(json.dumps(public, indent=2))
    return identity


def make_signed_request(identity, scheme, data, handshake):
    """Input: own private identity, chosen scheme, message bytes and server handshake.
    Output: request with message and signature or HMAC. Only public messages/tags leave the client.
    """
    import hmac

    request = {"message": data.hex()}
    if scheme == "RSA":
        request["signature"] = sign_message(RSA.import_key(identity["rsa_private"]), data).hex()
    elif scheme == "ElGamal":
        request["signature"] = elgamal_sign(data, identity["p"], identity["g"], identity["x"])
    elif scheme == "Schnorr":
        request["signature"] = schnorr_sign(
            data, identity["p"], identity["q"], identity["h"], identity["sx"]
        )
    elif scheme == "DH-HMAC":
        shared = dh_shared(identity["dh_private"], handshake["dh_public"])
        request["tag"] = hmac.new(shared, data, hashlib.sha256).hexdigest()
    else:
        raise ValueError("Choose RSA, ElGamal, Schnorr or DH-HMAC exactly.")
    return request


def exercise():
    """Input: identity setup or send choice, server address, scheme, message and alteration option.
    Output: public identity file, signature/tag and server verification. Set up before server starts.
    """
    folder = Path(__file__).resolve().parent
    identity = prepare_identity(folder)
    print("Public identity to trust at server:", folder / "client_public.json")
    if ask_text("Send now? n means setup only; y sends", "n").lower() != "y":
        return
    host = ask_text("Server host", "127.0.0.1")
    port = ask_int("Port", 5063, 1024, 65535)
    scheme = ask_text("Scheme: RSA/ElGamal/Schnorr/DH-HMAC", "RSA")
    data = ask_text("Message", "Client authenticates this message").encode()
    altered = ask_text("Alter after signing? y/n", "n").lower() == "y"
    with socket.create_connection((host, port), timeout=15) as connection:
        send_json(connection, {"scheme": scheme})
        handshake = receive_json(connection)
        request = make_signed_request(identity, scheme, data, handshake)
        print("Authentication value:", request.get("signature", request.get("tag")))
        if altered:
            request["message"] = (data + b"!").hex()
        send_json(connection, request)
        print("Server results:", receive_json(connection))


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
