import socket
import getpass
from crypto_helpers import *


def load_credentials(path, password):
    """Input: voter credential file and its password. Derive AES key and authenticate/decrypt private identity.
    Output: voter ID/election/private ElGamal identity. Wrong passwords fail GCM verification.
    """
    record = read_json(Path(path))
    if record is None:
        raise ValueError(
            "Credential file not found. Ask the election admin to register this voter."
        )
    key = PBKDF2(
        password.encode(),
        bytes.fromhex(record["salt"]),
        dkLen=32,
        count=200000,
        hmac_hash_module=SHA256,
    )
    return json.loads(open_seal(record["sealed"], key))


def packet_authentication(session, packet):
    """Input: AES session key and unsigned outer transport fields. Bind CBC ciphertext/IV, wrapped key and signature.
    Output: HMAC-SHA256 hex tag. This extra envelope check prevents unauthenticated CBC decryption.
    """
    fields = {
        name: packet[name] for name in ("wrapped_key", "encrypted_ballot", "hash", "signature")
    }
    mac_key = hashlib.sha256(session + b"ballot-envelope-authentication").digest()
    return hmac.new(mac_key, canonical(fields), hashlib.sha256).hexdigest()


def build_packet(public, credentials, candidate_id, constituency):
    """Input: trusted public config, unlocked voter identity, selected candidate and constituency.
    Output: outer encrypted packet and inner ballot. Numeric selection stays Paillier-encrypted even inside AES.
    """
    if (
        credentials["election_id"] != public["election_id"]
        or credentials["voter_id"] not in public["voters"]
    ):
        raise ValueError("Credential not registered for this election.")
    if not constituency.strip():
        raise ValueError("Constituency required.")
    ballot_id = secrets.token_hex(16)
    ballot = {
        "election_id": public["election_id"],
        "ballot_id": ballot_id,
        "voter_id": credentials["voter_id"],
        "constituency": constituency.strip(),
        "choice": encrypted_choice(
            public["paillier"], public["candidate_ids"], candidate_id, ballot_id
        ),
    }
    digest = hashlib.sha512(canonical(ballot)).hexdigest()
    signature = sign_ballot_hash(credentials["identity"], digest)
    session = get_random_bytes(32)
    encrypted = cbc_encrypt(canonical(ballot), session)
    wrapped = PKCS1_OAEP.new(RSA.import_key(public["rsa_public"]), hashAlgo=SHA256).encrypt(session)
    packet = {
        "encrypted_ballot": encrypted,
        "wrapped_key": wrapped.hex(),
        "hash": digest,
        "signature": signature,
    }
    packet["envelope_hmac"] = packet_authentication(session, packet)
    return packet, ballot


def send_request(host, port, request):
    """Input: reachable server address and timestamp/submit request. Exchange one framed JSON request/reply.
    Output: successful reply; ValueError for a server rejection. No private voter key leaves this program.
    """
    with socket.create_connection((host, port), timeout=30) as connection:
        send_json(connection, request)
        reply = receive_json(connection)
    if not reply.get("ok"):
        raise ValueError("Server rejected request: " + str(reply.get("error")))
    return reply


def cast_vote(public, credentials, candidate_id, constituency, host, port, outbox):
    """Input: unlocked voter identity, choice, constituency and server address. Timestamp then submit a fresh encrypted ballot.
    Output: receipt/ballot ID and saved ballot/packet files. Two TCP connections are used per vote.
    """
    packet, ballot = build_packet(public, credentials, candidate_id, constituency)
    outbox.mkdir(parents=True, exist_ok=True)
    # The ballot FILE contains encrypted selections, so hashing/verifying it does not expose a candidate ID.
    save_json(outbox / (ballot["ballot_id"] + ".ballot.json"), ballot, True)
    stamp = send_request(host, port, {"action": "timestamp", "packet": packet})["timestamp"]
    if not rsa_verify(
        public["timestamp_public"], canonical(timestamp_payload(stamp)), stamp["signature"]
    ):
        raise ValueError("Untrusted timestamp signature.")
    if stamp["hash"] != packet["hash"] or stamp["ballot_id"] != ballot["ballot_id"]:
        raise ValueError("Timestamp is for a different ballot.")
    packet["timestamp"] = stamp
    save_json(outbox / (ballot["ballot_id"] + ".packet.json"), packet, True)
    reply = send_request(host, port, {"action": "submit", "packet": packet})
    print("SHA-512 ballot hash:", packet["hash"], "ElGamal signature:", packet["signature"])
    print("AES-256-CBC ciphertext:", packet["encrypted_ballot"]["ciphertext"])
    print("RSA-4096 wrapped AES key:", packet["wrapped_key"])
    print(
        "Trusted timestamp:", display_time(stamp["at"]), "Accepted ballot ID:", reply["ballot_id"]
    )
    return reply


def main():
    """Input: voter menu, trusted config path, credential/password, selected candidate and server details.
    Output: encrypted ballot and accepted receipt. Start the server's Listen option in another terminal.
    """
    folder = Path(__file__).resolve().parent
    while True:
        print("\n1 Cast encrypted vote  0 Exit")
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice != "1":
                print("Choose 1 or 0.")
                continue
            config_path = Path(
                ask_text(
                    "Trusted public config path", str(folder / "storage" / "public_config.json")
                )
            )
            public = read_json(config_path)
            print("Candidates:", public["candidate_ids"], "Election:", public["election_id"])
            credential = Path(ask_text("Voter credential path"))
            unlocked = load_credentials(credential, getpass.getpass("Credential password: "))
            candidate = ask_int("Selected numerical candidate ID")
            constituency = ask_text("Constituency ID")
            host = ask_text("Server host", "127.0.0.1")
            port = ask_int("Port", 6044, 1024, 65535)
            cast_vote(public, unlocked, candidate, constituency, host, port, folder / "outbox")
        except (ValueError, KeyError, TypeError, OSError) as error:
            print("Rejected:", error)


if __name__ == "__main__":
    main()
