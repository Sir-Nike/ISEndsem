import json
import math
import time
import secrets
import hashlib
import hmac
import re
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from decimal import Decimal, InvalidOperation
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512, MD5
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, isPrime


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


def canonical(record):
    """Input: JSON-compatible record. Sort keys and remove irrelevant spaces consistently.
    Output: UTF-8 bytes. Hash/sign these exact bytes so dictionary formatting cannot change results.
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def read_json(path, default=None):
    """Input: JSON file path and optional missing-file default. Parse saved records.
    Output: decoded JSON. Invalid JSON raises an error instead of silently replacing damaged data.
    """
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def save_json(path, record, secret=False):
    """Input: path, record and secret-file flag. Write via a temporary file then replace atomically.
    Output: saved JSON file; returns nothing. Secret files receive owner-only permissions.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if secret:
        import os

        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(record, stream, indent=2, ensure_ascii=False, allow_nan=False)
    else:
        temporary.write_text(json.dumps(record, indent=2, ensure_ascii=False, allow_nan=False))
    temporary.replace(path)
    if secret:
        path.chmod(0o600)


def display_time(timestamp):
    """Input: Unix seconds. Format an explicit date/time in Asia/Kolkata.
    Output: readable timestamp string. Use for key expiry, voting windows and audit displays.
    """
    return datetime.fromtimestamp(timestamp, ZoneInfo("Asia/Kolkata")).isoformat(timespec="seconds")


def seal(data, key):
    """Input: plaintext bytes and 16/24/32-byte AES key. Encrypt/authenticate using GCM.
    Output: JSON-safe nonce/ciphertext/tag dictionary. Save all three for verified decryption.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return {"nonce": cipher.nonce.hex(), "ciphertext": encrypted.hex(), "tag": tag.hex()}


def open_seal(envelope, key):
    """Input: saved AES-GCM envelope and matching key. Verify the tag before returning data.
    Output: plaintext bytes; wrong keys/modified ciphertext raise ValueError.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(envelope["nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(envelope["ciphertext"]), bytes.fromhex(envelope["tag"])
    )


def cbc_encrypt(data, key):
    """Input: plaintext bytes and AES key. Generate a fresh IV, PKCS#7-pad and CBC-encrypt.
    Output: hex IV/ciphertext dictionary. Sign the envelope separately to detect modification.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    return {"iv": cipher.iv.hex(), "ciphertext": cipher.encrypt(pad(data, AES.block_size)).hex()}


def cbc_decrypt(envelope, key):
    """Input: authenticated CBC envelope and original AES key. Decrypt and remove padding.
    Output: plaintext bytes. Call only after verifying the enclosing signature/integrity checks.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes.fromhex(envelope["iv"]))
    return unpad(cipher.decrypt(bytes.fromhex(envelope["ciphertext"])), AES.block_size)


def rsa_sign(private_pem, data, algorithm="sha256"):
    """Input: RSA private PEM, bytes to sign and sha256/md5/sha512 selection. Hash once and sign.
    Output: PKCS#1 v1.5 signature as hex. Private keys remain local; public keys verify.
    """
    hash_module = {"sha256": SHA256, "md5": MD5, "sha512": SHA512}[algorithm]
    return pkcs1_15.new(RSA.import_key(private_pem)).sign(hash_module.new(data)).hex()


def rsa_verify(public_pem, data, signature, algorithm="sha256"):
    """Input: trusted RSA public PEM, original bytes, signature hex and hash selection.
    Output: True if the signature matches; False for altered data, key or signature encoding.
    """
    try:
        hash_module = {"sha256": SHA256, "md5": MD5, "sha512": SHA512}[algorithm]
        pkcs1_15.new(RSA.import_key(public_pem)).verify(
            hash_module.new(data), bytes.fromhex(signature)
        )
        return True
    except (ValueError, TypeError, KeyError):
        return False


def rsa_pair(bits=2048):
    """Input: RSA modulus bits. Ask PyCryptodome to generate a fresh key pair.
    Output: dictionary of private/public PEM strings. Save the private part in a secret file.
    """
    key = RSA.generate(bits)
    return {"private": key.export_key().decode(), "public": key.publickey().export_key().decode()}


def random_unit(n):
    """Input: modulus. Choose a random value in 1..n-1 that has a modular inverse.
    Output: coprime random integer. Used as Paillier randomness and proof randomness.
    """
    while True:
        value = secrets.randbelow(n - 1) + 1
        if math.gcd(value, n) == 1:
            return value


def paillier_encrypt(public, value, return_randomness=False):
    """Input: public key and integer in 0..n-1; optionally request the random witness.
    Output: ciphertext, or (ciphertext,r) for ballot proofs. Never publish an individual vote's r.
    """
    n = public["n"]
    if not isinstance(value, int) or not 0 <= value < n:
        raise ValueError("Paillier input outside 0..n-1.")
    r = random_unit(n)
    ciphertext = pow(public["g"], value, n * n) * pow(r, n, n * n) % (n * n)
    return (ciphertext, r) if return_randomness else ciphertext


def check_ciphertext(public, ciphertext):
    """Input: Paillier public key and untrusted ciphertext integer. Validate its group/range.
    Output: nothing; raise ValueError if it is not an invertible element modulo n squared.
    """
    n = public["n"]
    if (
        not isinstance(ciphertext, int)
        or not 0 < ciphertext < n * n
        or math.gcd(ciphertext, n) != 1
    ):
        raise ValueError("Invalid Paillier ciphertext.")


def encrypted_sum(public, ciphertexts):
    """Input: public Paillier key and ciphertext list. Multiply valid ciphertexts modulo n squared.
    Output: encrypted sum modulo n. This function has no private-key parameter and cannot decrypt inputs.
    """
    result = 1
    n2 = public["n"] ** 2
    for value in ciphertexts:
        check_ciphertext(public, value)
        result = result * value % n2
    return result


def token(key, text):
    """Input: secret HMAC key and already normalized lookup string. Compute deterministic keyed hash.
    Output: hex lookup token. A search computes the same token without bulk decryption.
    """
    return hmac.new(key, text.encode(), hashlib.sha256).hexdigest()


def setup_accounts(path, roles):
    """Input: account file path and role names. On first use ask for each role's new password twice.
    Output: saved salted PBKDF2 password records. Existing passwords are never silently replaced.
    """
    import getpass

    existing = read_json(path)
    if existing is not None:
        return existing
    accounts = {}
    print("First run: create separate passwords for these local lab roles:", ", ".join(roles))
    for role in roles:
        password = getpass.getpass("New password for " + role + ": ")
        if not password or password != getpass.getpass("Confirm password: "):
            raise ValueError("Passwords must be nonempty and match.")
        salt = get_random_bytes(16)
        digest = PBKDF2(password.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA256)
        accounts[role] = {"role": role, "salt": salt.hex(), "password_hash": digest.hex()}
    save_json(path, accounts, True)
    return accounts


def authenticate(accounts, username, password):
    """Input: saved accounts, username and entered password. Derive and compare the salted password hash.
    Output: role string on success; ValueError on unknown account or wrong password.
    """
    if username not in accounts:
        raise ValueError("Invalid login.")
    record = accounts[username]
    received = PBKDF2(
        password.encode(),
        bytes.fromhex(record["salt"]),
        dkLen=32,
        count=200000,
        hmac_hash_module=SHA256,
    )
    if not hmac.compare_digest(received.hex(), record["password_hash"]):
        raise ValueError("Invalid login.")
    return record["role"]


def login(accounts):
    """Input: username and hidden password from the terminal. Authenticate a previously created account.
    Output: username and assigned role; callers use that role to choose the allowed menu.
    """
    import getpass

    username = ask_text("Username")
    role = authenticate(accounts, username, getpass.getpass("Password: "))
    return username, role


def require_role(actual, allowed):
    """Input: authenticated role and allowed-role collection. Check permission inside the operation itself.
    Output: nothing on success; PermissionError on denial. Menus alone are not authorization checks.
    """
    if actual not in allowed:
        raise PermissionError("This role cannot perform that operation.")


def audit(folder, event, details, private_pem):
    """Input: audit directory, event name, details and signing key. Chain and sign a new audit entry.
    Output: appended JSONL event. The previous-entry digest exposes edits, reordering and gaps.
    """
    path = Path(folder) / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text().splitlines() if path.exists() else []
    previous = hashlib.sha256(lines[-1].encode()).hexdigest() if lines else "0" * 64
    entry = {
        "sequence": len(lines) + 1,
        "time": time.time(),
        "event": event,
        "details": details,
        "previous": previous,
    }
    entry["signature"] = rsa_sign(private_pem, canonical(entry))
    with path.open("a") as stream:
        stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def verify_audit(folder, public_pem):
    """Input: audit directory and trusted signing public key. Verify signatures and previous-entry chain.
    Output: True when existing entries are intact. External anchoring is needed to detect deletion of the final suffix.
    """
    path = Path(folder) / "audit.jsonl"
    previous = "0" * 64
    if not path.exists():
        return True
    try:
        for index, line in enumerate(path.read_text().splitlines(), 1):
            entry = json.loads(line)
            signature = entry.pop("signature")
            if (
                entry["sequence"] != index
                or entry["previous"] != previous
                or not rsa_verify(public_pem, canonical(entry), signature)
            ):
                return False
            previous = hashlib.sha256(line.encode()).hexdigest()
        return True
    except (ValueError, KeyError, TypeError):
        return False


from fractions import Fraction


def safe_prime(bits):
    """Input: prime bit length. Generate q and prime p=2q+1 for threshold Paillier/ElGamal groups.
    Output: (p,q). Small sizes are for quick practice; generation time varies.
    """
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            return p, q


def threshold_keys(bits=512, count=3, threshold=2):
    """Input: modulus bits, trustee count and required quorum. Generate dealer-based threshold Paillier.
    Output: public parameters and separate secret shares. No lambda/mu/full decryption key is saved.
    """
    if not 2 <= threshold <= count <= 10 or bits < 128:
        raise ValueError("Invalid threshold parameters.")
    while True:
        p, p0 = safe_prime(bits // 2)
        q, q0 = safe_prime(bits - bits // 2)
        if len({p, q, p0, q0}) < 4:
            continue
        n = p * q
        m = p0 * q0
        if math.gcd(n, m) == 1:
            break
    modulus = n * m
    d = m * pow(m, -1, n) % modulus
    coefficients = [d] + [secrets.randbelow(modulus) for _ in range(threshold - 1)]
    coefficients[-1] = secrets.randbelow(modulus - 1) + 1
    delta = math.factorial(count)
    v = pow(random_unit(n * n), 2, n * n)
    shares = [
        {
            "id": i,
            "secret": sum(a * pow(i, j, modulus) for j, a in enumerate(coefficients)) % modulus,
        }
        for i in range(1, count + 1)
    ]
    public = {
        "n": n,
        "g": n + 1,
        "count": count,
        "threshold": threshold,
        "delta": delta,
        "v": v,
        "verification": {
            str(share["id"]): pow(v, delta * share["secret"], n * n) for share in shares
        },
    }
    return public, shares


def proof_challenge(record):
    """Input: public proof transcript dictionary. Hash it into a 128-bit Fiat-Shamir challenge.
    Output: challenge integer. Context/domain strings keep unrelated proof types separate.
    """
    return int.from_bytes(hashlib.sha256(canonical(record)).digest(), "big") % (1 << 128)


def partial_decrypt(public, share, ciphertext, context):
    """Input: public parameters, ONE trustee's secret share, aggregate ciphertext and request context.
    Output: partial decryption plus equality-of-exponents proof. It never reconstructs a private key.
    """
    check_ciphertext(public, ciphertext)
    n2 = public["n"] ** 2
    identity = share["id"]
    exponent = public["delta"] * share["secret"]
    partial = pow(ciphertext, 2 * exponent, n2)
    randomness = secrets.randbits(public["n"].bit_length() * 2 + 384)
    a = pow(public["v"], randomness, n2)
    b = pow(pow(ciphertext, 4, n2), randomness, n2)
    challenge = proof_challenge(
        {
            "domain": "partial-v1",
            "context": context,
            "id": identity,
            "c": ciphertext,
            "partial": partial,
            "a": a,
            "b": b,
        }
    )
    return {
        "id": identity,
        "partial": partial,
        "a": a,
        "b": b,
        "z": randomness + challenge * exponent,
    }


def verify_partial(public, ciphertext, part, context):
    """Input: public key, aggregate, supplied partial/proof and bound request context.
    Output: boolean proving this partial uses the trustee's registered secret exponent.
    """
    try:
        n2 = public["n"] ** 2
        identity = part["id"]
        v_i = public["verification"][str(identity)]
        if not 1 <= identity <= public["count"] or not 0 <= part["z"] < (
            1 << (public["n"].bit_length() * 2 + 520)
        ):
            return False
        for name in ("partial", "a", "b"):
            if not 0 < part[name] < n2 or math.gcd(part[name], public["n"]) != 1:
                return False
        challenge = proof_challenge(
            {
                "domain": "partial-v1",
                "context": context,
                "id": identity,
                "c": ciphertext,
                "partial": part["partial"],
                "a": part["a"],
                "b": part["b"],
            }
        )
        first = pow(public["v"], part["z"], n2) == part["a"] * pow(v_i, challenge, n2) % n2
        second = (
            pow(pow(ciphertext, 4, n2), part["z"], n2)
            == part["b"] * pow(pow(part["partial"], 2, n2), challenge, n2) % n2
        )
        return first and second
    except (ValueError, KeyError, TypeError, OverflowError):
        return False


def combine_partials(public, ciphertext, parts, context):
    """Input: aggregate ciphertext and enough distinct verified partial decryptions for its request.
    Output: final plaintext aggregate. Integer Lagrange weights combine partials without recovering secret shares.
    """
    if len(parts) < public["threshold"] or len({part["id"] for part in parts}) != len(parts):
        raise ValueError("Need enough DISTINCT trustees.")
    if not all(verify_partial(public, ciphertext, part, context) for part in parts):
        raise ValueError("Invalid or wrong-context partial proof.")
    chosen = parts[: public["threshold"]]
    identities = [part["id"] for part in chosen]
    n = public["n"]
    combined = 1
    for part in chosen:
        coefficient = Fraction(public["delta"], 1)
        for other in identities:
            if other != part["id"]:
                coefficient *= Fraction(other, other - part["id"])
        if coefficient.denominator != 1:
            raise ValueError("Nonintegral threshold coefficient.")
        combined = combined * pow(part["partial"], 2 * coefficient.numerator, n * n) % (n * n)
    if (combined - 1) % n:
        raise ValueError("Invalid combined threshold decryption.")
    return ((combined - 1) // n) * pow(4 * public["delta"] ** 2, -1, n) % n


def elgamal_identity(bits=512):
    """Input: finite-field size. Generate safe prime, full generator and ElGamal signing identity.
    Output: private x and public p/g/y dictionary. The client keeps x secret.
    """
    p, q = safe_prime(bits)
    g = 2
    while pow(g, 2, p) == 1 or pow(g, q, p) == 1:
        g += 1
    x = secrets.randbelow(p - 2) + 1
    return {"p": p, "g": g, "y": pow(g, x, p), "x": x}


def sign_ballot_hash(identity, digest_hex):
    """Input: private ElGamal identity and SHA-512 ballot digest. Sign that digest directly.
    Output: (r,s) signature list. A fresh invertible nonce is required for every ballot.
    """
    p, g, x = identity["p"], identity["g"], identity["x"]
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    h_value = int(digest_hex, 16)
    return [r, ((h_value - x * r) * pow(k, -1, p - 1)) % (p - 1)]


def verify_ballot_hash(identity, digest_hex, signature):
    """Input: trusted public ElGamal identity, SHA-512 digest and (r,s) signature.
    Output: validity boolean. Never accept a public key sent by a new unregistered voter.
    """
    try:
        p, g, y = identity["p"], identity["g"], identity["y"]
        r, s = signature
        if not 0 < r < p or not 0 <= s < p - 1:
            return False
        return pow(g, int(digest_hex, 16), p) == pow(y, r, p) * pow(r, s, p) % p
    except (ValueError, TypeError, KeyError):
        return False


def bit_proof(public, ciphertext, bit, r, context):
    """Input: encryption of known bit 0/1, its secret randomness and unique ballot/candidate context.
    Output: OR proof that the encrypted number is 0 or 1 without disclosing which bit.
    """
    if bit not in (0, 1):
        raise ValueError("Proof input must be a bit.")
    n = public["n"]
    n2 = n * n
    bound = 1 << 128
    values = [ciphertext, ciphertext * pow(public["g"], -1, n2) % n2]
    fake = 1 - bit
    challenges = [0, 0]
    responses = [0, 0]
    commitments = [0, 0]
    challenges[fake] = secrets.randbelow(bound)
    responses[fake] = random_unit(n)
    commitments[fake] = pow(responses[fake], n, n2) * pow(values[fake], -challenges[fake], n2) % n2
    u = random_unit(n)
    commitments[bit] = pow(u, n, n2)
    total = proof_challenge(
        {"domain": "bit-v1", "context": context, "c": ciphertext, "a": commitments}
    )
    challenges[bit] = (total - challenges[fake]) % bound
    responses[bit] = u * pow(r, challenges[bit], n) % n
    return {"a": commitments, "e": challenges, "z": responses}


def verify_bit(public, ciphertext, proof, context):
    """Input: Paillier ciphertext, OR proof and its ballot/candidate context. Verify both challenge branches.
    Output: boolean. This prevents encrypted 2, negative values or oversized fake vote counts.
    """
    try:
        check_ciphertext(public, ciphertext)
        n = public["n"]
        n2 = n * n
        if any(len(proof[name]) != 2 for name in ("a", "e", "z")):
            return False
        values = [ciphertext, ciphertext * pow(public["g"], -1, n2) % n2]
        expected = proof_challenge(
            {"domain": "bit-v1", "context": context, "c": ciphertext, "a": proof["a"]}
        )
        if sum(proof["e"]) % (1 << 128) != expected:
            return False
        for i in (0, 1):
            if (
                not 0 <= proof["e"][i] < (1 << 128)
                or not 0 < proof["z"][i] < n
                or math.gcd(proof["z"][i], n) != 1
            ):
                return False
            if not 0 < proof["a"][i] < n2 or math.gcd(proof["a"][i], n) != 1:
                return False
            if pow(proof["z"][i], n, n2) != proof["a"][i] * pow(values[i], proof["e"][i], n2) % n2:
                return False
        return True
    except (ValueError, KeyError, TypeError, IndexError):
        return False


def encrypted_choice(public, candidate_ids, selected_id, ballot_id):
    """Input: public Paillier key, configured candidate IDs, selected ID and fresh ballot ID.
    Output: encrypted numeric ID plus encrypted one-hot vector and proofs linking both representations.
    """
    if selected_id not in candidate_ids:
        raise ValueError("Unknown candidate.")
    vector = []
    proofs = []
    randomness = []
    for candidate in candidate_ids:
        bit = int(candidate == selected_id)
        c, r = paillier_encrypt(public, bit, True)
        vector.append(c)
        randomness.append(r)
        proofs.append(bit_proof(public, c, bit, r, ballot_id + ":" + str(candidate)))
    encrypted_id, r_id = paillier_encrypt(public, selected_id, True)
    n = public["n"]
    product = 1
    weighted = 1
    for candidate, r in zip(candidate_ids, randomness):
        product = product * r % n
        weighted = weighted * pow(r, candidate, n) % n
    return {
        "encrypted_id": encrypted_id,
        "vector": vector,
        "proofs": proofs,
        "sum_witness": product,
        "id_link_witness": r_id * pow(weighted, -1, n) % n,
    }


def verify_choice(public, candidate_ids, choice, ballot_id):
    """Input: encrypted choice bundle and fixed candidate list. Verify bit proofs, one-hot sum and numeric-ID link.
    Output: True only for one valid encrypted selection. Individual votes are never decrypted.
    """
    try:
        n = public["n"]
        n2 = n * n
        vector = choice["vector"]
        proofs = choice["proofs"]
        if len(vector) != len(candidate_ids) or len(proofs) != len(vector):
            return False
        check_ciphertext(public, choice["encrypted_id"])
        for candidate, c, proof in zip(candidate_ids, vector, proofs):
            if not verify_bit(public, c, proof, ballot_id + ":" + str(candidate)):
                return False
        for name in ("sum_witness", "id_link_witness"):
            if not 0 < choice[name] < n or math.gcd(choice[name], n) != 1:
                return False
        vector_sum = encrypted_sum(public, vector)
        if vector_sum * pow(public["g"], -1, n2) % n2 != pow(choice["sum_witness"], n, n2):
            return False
        weighted = 1
        for candidate, c in zip(candidate_ids, vector):
            weighted = weighted * pow(c, candidate, n2) % n2
        ratio = choice["encrypted_id"] * pow(weighted, -1, n2) % n2
        return ratio == pow(choice["id_link_witness"], n, n2)
    except (ValueError, KeyError, TypeError):
        return False


def send_json(connection, record):
    """Input: connected TCP socket and JSON record. Send a 4-byte size then exact JSON bytes.
    Output: transmitted frame. Maximum 4 MB prevents unbounded message allocation.
    """
    data = canonical(record)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("Frame too large.")
    connection.sendall(len(data).to_bytes(4, "big") + data)


def receive_exact(connection, size):
    """Input: TCP socket and exact byte count. Keep reading because TCP can split a send into pieces.
    Output: complete bytes, or ValueError on an early peer disconnect.
    """
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise ValueError("Connection closed during a message.")
        result.extend(part)
    return bytes(result)


def receive_json(connection):
    """Input: connected socket. Read a bounded length-framed JSON message.
    Output: parsed JSON value. Use with send_json for request/reply exchanges.
    """
    size = int.from_bytes(receive_exact(connection, 4), "big")
    if size > 4 * 1024 * 1024:
        raise ValueError("Incoming frame too large.")
    return json.loads(receive_exact(connection, size))


def timestamp_payload(stamp):
    """Input: signed timestamp dictionary. Remove its signature before verification.
    Output: timestamp fields bound to ballot hash, voter, ballot ID, issuer time and serial.
    """
    return {name: value for name, value in stamp.items() if name != "signature"}


def validate_public_ballot(public, record):
    """Input: trusted election config and accepted ballot with encrypted choices/signature/timestamp.
    Output: True after voter, SHA-512, ElGamal, timestamp, window and encrypted-choice proof checks.
    """
    try:
        ballot = record["ballot"]
        digest = hashlib.sha512(canonical(ballot)).hexdigest()
        if ballot["election_id"] != public["election_id"] or digest != record["hash"]:
            return False
        if not isinstance(ballot["constituency"], str) or not ballot["constituency"].strip():
            return False
        voter = public["voters"][ballot["voter_id"]]
        if not verify_ballot_hash(voter, digest, record["signature"]):
            return False
        stamp = record["timestamp"]
        if (
            stamp["ballot_id"] != ballot["ballot_id"]
            or stamp["voter_id"] != ballot["voter_id"]
            or stamp["hash"] != digest
        ):
            return False
        if not public["starts_at"] <= stamp["at"] <= public["ends_at"]:
            return False
        if not stamp["at"] <= record["received_at"] <= public["ends_at"]:
            return False
        if not rsa_verify(
            public["timestamp_public"], canonical(timestamp_payload(stamp)), stamp["signature"]
        ):
            return False
        return verify_choice(
            public["paillier"], public["candidate_ids"], ballot["choice"], ballot["ballot_id"]
        )
    except (ValueError, KeyError, TypeError):
        return False


def tally_payload(request):
    """Input: saved signed tally request. Remove request signature before hashing/verifying.
    Output: complete public tally request fields, including all accepted encrypted ballots.
    """
    return {name: value for name, value in request.items() if name != "signature"}


def validate_tally_request(public, request):
    """Input: trusted public configuration and server-signed final tally request.
    Output: nothing on success. Reject invalid/duplicate ballots or aggregates that differ from recomputation.
    """
    if request["election_id"] != public["election_id"] or not request["closed"]:
        raise ValueError("Not a closed election request.")
    if not rsa_verify(
        public["rsa_public"], canonical(tally_payload(request)), request["signature"]
    ):
        raise ValueError("Invalid tally request signature.")
    records = request["ballots"]
    if len({row["ballot"]["voter_id"] for row in records}) != len(records) or len(
        {row["ballot"]["ballot_id"] for row in records}
    ) != len(records):
        raise ValueError("Duplicate ballot/voter in request.")
    if any(not validate_public_ballot(public, row) for row in records):
        raise ValueError("Invalid accepted ballot in tally.")
    if len(records) >= public["paillier"]["n"]:
        raise ValueError("Tally would wrap modulo n.")
    expected = [
        encrypted_sum(public["paillier"], [row["ballot"]["choice"]["vector"][i] for row in records])
        for i in range(len(public["candidate_ids"]))
    ]
    if request["aggregates"] != expected:
        raise ValueError("Aggregate differs from accepted encrypted ballots.")


def packet_authentication(session, packet):
    """Input: session key and outer packet fields. Recompute authenticated CBC-envelope HMAC.
    Output: tag hex. Server compares it before CBC decryption; timestamp has its own RSA signature.
    """
    fields = {
        name: packet[name] for name in ("wrapped_key", "encrypted_ballot", "hash", "signature")
    }
    mac_key = hashlib.sha256(session + b"ballot-envelope-authentication").digest()
    return hmac.new(mac_key, canonical(fields), hashlib.sha256).hexdigest()
