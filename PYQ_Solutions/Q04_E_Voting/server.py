import socket
import getpass
from crypto_helpers import *


def save_election(folder, public, state, keys):
    """Input: configuration, election state and server identity. Sign the whole state and save public/state files.
    Output: persistent JSON files. Index/voter-list tampering is covered by the state signature.
    """
    state["config_hash"] = hashlib.sha256(canonical(public)).hexdigest()
    unsigned = {name: value for name, value in state.items() if name != "signature"}
    state["signature"] = rsa_sign(keys["rsa"]["private"], canonical(unsigned))
    save_json(folder / "public_config.json", public)
    save_json(folder / "election.json", state)


def initialize_election(folder, duration_minutes=60, paillier_bits=512):
    """Input: storage directory, window length and teaching Paillier size. Generate RSA-4096 and 2-of-3 shares once.
    Output: public config, server keys and verified state. Secret trustee shares are separate setup handoff files.
    """
    folder.mkdir(parents=True, exist_ok=True)
    keys = read_json(folder / "server_keys.json")
    public = read_json(folder / "public_config.json")
    state = read_json(folder / "election.json")
    if keys is None:
        if public is not None or state is not None:
            raise ValueError("Missing server keys for an existing election; restore the keys.")
        if not 1 <= duration_minutes <= 1440:
            raise ValueError("Window must be 1..1440 minutes.")
        threshold_public, shares = threshold_keys(paillier_bits, 3, 2)
        rsa = rsa_pair(4096)
        timestamp = rsa_pair(2048)
        keys = {"rsa": rsa, "timestamp": timestamp, "index": get_random_bytes(32).hex()}
        start = time.time()
        public = {
            "election_id": secrets.token_hex(12),
            "rsa_public": rsa["public"],
            "timestamp_public": timestamp["public"],
            "paillier": threshold_public,
            "candidate_ids": [1, 2, 3],
            "voters": {},
            "starts_at": start,
            "ends_at": start + duration_minutes * 60,
        }
        state = {
            "ballots": {},
            "voted": [],
            "constituency_index": {},
            "time_index": {},
            "closed": False,
        }
        save_json(folder / "server_keys.json", keys, True)
        for share in shares:
            save_json(
                folder / "trustee_setup" / f'trustee_{share["id"]}.json',
                {"election_id": public["election_id"], "share": share},
                True,
            )
        save_election(folder, public, state, keys)
        print(
            "Deliver each trustee_setup share file privately to its own trustee. The server does not need these files to accept votes."
        )
    else:
        if public is None or state is None:
            raise ValueError("Existing election files are incomplete.")
        unsigned = {name: value for name, value in state.items() if name != "signature"}
        if not rsa_verify(keys["rsa"]["public"], canonical(unsigned), state.get("signature", "")):
            raise ValueError("Saved election state signature failed.")
        if public["rsa_public"] != keys["rsa"]["public"]:
            raise ValueError("Server public identity mismatch.")
        if state.get("config_hash") != hashlib.sha256(canonical(public)).hexdigest():
            raise ValueError("Public configuration was modified.")
    print("Window:", display_time(public["starts_at"]), "to", display_time(public["ends_at"]))
    return public, keys, state


def register_voter(folder, public, keys, state, role, voter_id, password):
    """Input: admin role, unique safe voter ID and private-file password. Generate an ElGamal voter identity.
    Output: password-encrypted credential file path and updated trusted voter registry.
    """
    require_role(role, ("admin",))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", voter_id) or voter_id in public["voters"]:
        raise ValueError("Use a new voter ID with letters/digits/underscore/hyphen only.")
    if not password:
        raise ValueError("Voter credential password required.")
    identity = elgamal_identity(512)
    public["voters"][voter_id] = {name: identity[name] for name in ("p", "g", "y")}
    salt = get_random_bytes(16)
    key = PBKDF2(password.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA256)
    credentials = {"voter_id": voter_id, "election_id": public["election_id"], "identity": identity}
    path = folder / "voter_credentials" / f"{voter_id}.json"
    save_json(path, {"salt": salt.hex(), "sealed": seal(canonical(credentials), key)}, True)
    # Bind trusted configuration into server-signed state, in addition to signing state indexes.
    save_election(folder, public, state, keys)
    audit(folder, "voter_registered", {"voter": voter_id}, keys["rsa"]["private"])
    return path


def decrypt_ballot_packet(public, keys, packet):
    """Input: AES-CBC ballot envelope, RSA-wrapped AES key, SHA-512 digest and ElGamal signature.
    Output: validated inner ballot with Paillier-encrypted choices. It never decrypts a candidate value.
    """
    session = PKCS1_OAEP.new(RSA.import_key(keys["rsa"]["private"]), hashAlgo=SHA256).decrypt(
        bytes.fromhex(packet["wrapped_key"])
    )
    if len(session) != 32:
        raise ValueError("Ballot AES session key must be 32 bytes.")
    if not hmac.compare_digest(packet_authentication(session, packet), packet["envelope_hmac"]):
        raise ValueError("Ballot envelope authentication failed.")
    ballot = json.loads(cbc_decrypt(packet["encrypted_ballot"], session))
    digest = hashlib.sha512(canonical(ballot)).hexdigest()
    if digest != packet["hash"]:
        raise ValueError("SHA-512 ballot mismatch.")
    if ballot["election_id"] != public["election_id"] or ballot["voter_id"] not in public["voters"]:
        raise ValueError("Unknown election/voter.")
    if not verify_ballot_hash(public["voters"][ballot["voter_id"]], digest, packet["signature"]):
        raise ValueError("ElGamal signature failed.")
    if not isinstance(ballot["constituency"], str) or not ballot["constituency"].strip():
        raise ValueError("Constituency required.")
    if not re.fullmatch(r"[0-9a-f]{32}", ballot["ballot_id"]):
        raise ValueError("Invalid ballot ID.")
    if not verify_choice(
        public["paillier"], public["candidate_ids"], ballot["choice"], ballot["ballot_id"]
    ):
        raise ValueError("Invalid encrypted vote/one-hot proof.")
    return ballot


def issue_timestamp(public, keys, state, packet, now=None):
    """Input: validated signed ballot packet and server-side trusted clock. Issue a timestamp bound to this ballot hash.
    Output: RSA-signed timestamp token. Client-provided timestamps are never trusted.
    """
    now = time.time() if now is None else now
    if state["closed"] or not public["starts_at"] <= now <= public["ends_at"]:
        raise ValueError("Voting period is closed.")
    ballot = decrypt_ballot_packet(public, keys, packet)
    if ballot["voter_id"] in state["voted"]:
        raise ValueError("Voter has already voted.")
    stamp = {
        "at": now,
        "hash": packet["hash"],
        "ballot_id": ballot["ballot_id"],
        "voter_id": ballot["voter_id"],
        "serial": secrets.token_hex(16),
    }
    stamp["signature"] = rsa_sign(keys["timestamp"]["private"], canonical(stamp))
    return stamp


def accept_ballot(folder, public, keys, state, packet, now=None):
    """Input: signed/encrypted ballot packet and trusted timestamp. Verify all checks before persisting.
    Output: accepted ballot ID. Reject duplicate voters, replayed ballots, bad proofs or expired submissions.
    """
    now = time.time() if now is None else now
    if state["closed"] or not public["starts_at"] <= now <= public["ends_at"]:
        raise ValueError("Voting window closed.")
    ballot = decrypt_ballot_packet(public, keys, packet)
    if ballot["voter_id"] in state["voted"] or ballot["ballot_id"] in state["ballots"]:
        raise ValueError("Duplicate vote or replay.")
    record = {
        "ballot": ballot,
        "hash": packet["hash"],
        "signature": packet["signature"],
        "timestamp": packet["timestamp"],
        "received_at": now,
    }
    if not validate_public_ballot(public, record):
        raise ValueError("Timestamp or signed ballot validation failed.")
    bid = ballot["ballot_id"]
    state["ballots"][bid] = record
    state["voted"].append(ballot["voter_id"])
    constituency = token(
        bytes.fromhex(keys["index"]), "constituency:" + ballot["constituency"].casefold()
    )
    minute = token(
        bytes.fromhex(keys["index"]), "minute:" + str(int(record["timestamp"]["at"] // 60))
    )
    state["constituency_index"].setdefault(constituency, []).append(bid)
    state["time_index"].setdefault(minute, []).append(bid)
    save_election(folder, public, state, keys)
    audit(folder, "ballot_accepted", {"ballot_id": bid}, keys["rsa"]["private"])
    return bid


def serve_votes(folder, public, keys, state, role, host, port, connections):
    """Input: admin role, bind address and request count. Serve timestamp/submission messages over framed TCP.
    Output: signed timestamps or acceptance/rejection replies. Each client vote normally makes TWO connections.
    """
    require_role(role, ("admin",))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        listener.settimeout(120)
        print("Listening on", host, port, flush=True)
        for _ in range(connections):
            connection, address = listener.accept()
            with connection:
                connection.settimeout(20)
                try:
                    request = receive_json(connection)
                    if request["action"] == "timestamp":
                        reply = {
                            "ok": True,
                            "timestamp": issue_timestamp(public, keys, state, request["packet"]),
                        }
                    elif request["action"] == "submit":
                        reply = {
                            "ok": True,
                            "ballot_id": accept_ballot(
                                folder, public, keys, state, request["packet"]
                            ),
                        }
                    else:
                        raise ValueError("Unknown request action.")
                    send_json(connection, reply)
                except (ValueError, KeyError, TypeError, OSError) as error:
                    send_json(connection, {"ok": False, "error": str(error)})
                    audit(folder, "ballot_rejected", {"reason": str(error)}, keys["rsa"]["private"])
                    print("Rejected ballot request:", error)


def search_constituency(public, keys, state, role, constituency):
    """Input: admin/auditor role and constituency keyword. Query HMAC index without decrypting choices.
    Output: ballot ID list after validating matching signatures and exact constituency metadata.
    """
    require_role(role, ("admin", "auditor"))
    lookup = token(bytes.fromhex(keys["index"]), "constituency:" + constituency.casefold())
    ids = state["constituency_index"].get(lookup, [])
    for bid in ids:
        row = state["ballots"][bid]
        if (
            not validate_public_ballot(public, row)
            or row["ballot"]["constituency"].casefold() != constituency.casefold()
        ):
            raise ValueError("Invalid indexed ballot.")
    return ids


def search_time_range(public, keys, state, role, start, end):
    """Input: admin/auditor role and inclusive Unix-second range. Query keyed minute buckets then exact timestamps.
    Output: matching ballot IDs. Vote ciphertexts remain encrypted; maximum range is one day.
    """
    require_role(role, ("admin", "auditor"))
    if not start <= end or end - start > 86400:
        raise ValueError("Use an ordered range of at most 24 hours.")
    found = set()
    for minute in range(int(start // 60), int(end // 60) + 1):
        lookup = token(bytes.fromhex(keys["index"]), "minute:" + str(minute))
        for bid in state["time_index"].get(lookup, []):
            row = state["ballots"][bid]
            if not validate_public_ballot(public, row):
                raise ValueError("Invalid stored ballot.")
            if start <= row["timestamp"]["at"] <= end:
                found.add(bid)
    return sorted(found)


def close_election(folder, public, keys, state, role):
    """Input: admin role and current election state. Irreversibly close this local election to new votes.
    Output: signed closed state persisted and audit event. Existing accepted ballots remain encrypted.
    """
    require_role(role, ("admin",))
    state["closed"] = True
    save_election(folder, public, state, keys)
    audit(folder, "election_closed", {}, keys["rsa"]["private"])


def export_tally(folder, public, keys, state, role):
    """Input: admin role after voting closes. Verify every accepted ballot and multiply each candidate's encrypted bits.
    Output: signed tally_request.json containing only encrypted votes and final aggregate ciphertexts.
    """
    require_role(role, ("admin",))
    if not state["closed"] and time.time() <= public["ends_at"]:
        raise ValueError("Close voting first.")
    if not state["closed"]:
        close_election(folder, public, keys, state, role)
    records = list(state["ballots"].values())
    if not records:
        raise ValueError("No ballots to tally.")
    if any(not validate_public_ballot(public, row) for row in records):
        raise ValueError("Tampered accepted ballot.")
    aggregate = [
        encrypted_sum(public["paillier"], [row["ballot"]["choice"]["vector"][i] for row in records])
        for i in range(len(public["candidate_ids"]))
    ]
    request = {
        "election_id": public["election_id"],
        "request_id": secrets.token_hex(16),
        "closed": True,
        "created_at": time.time(),
        "ballots": records,
        "aggregates": aggregate,
    }
    request["signature"] = rsa_sign(keys["rsa"]["private"], canonical(request))
    validate_tally_request(public, request)
    path = folder / "tally_request.json"
    save_json(path, request)
    return path


def finalize_tally(folder, public, keys, state, role, partial_paths):
    """Input: admin role and partial-response files from enough distinct trustees. Validate request/response bindings and proofs.
    Output: candidate-count dictionary decrypted ONLY from aggregate ciphertexts, saved with signature.
    """
    require_role(role, ("admin",))
    if not state["closed"]:
        raise ValueError("Voting must be closed.")
    request = read_json(folder / "tally_request.json")
    validate_tally_request(public, request)
    # Refuse a stale subset request if current persisted election ballots differ.
    if canonical(request["ballots"]) != canonical(list(state["ballots"].values())):
        raise ValueError("Stale tally request.")
    digest = hashlib.sha256(canonical(request)).hexdigest()
    responses = [read_json(Path(path)) for path in partial_paths]
    if any(
        response["request_hash"] != digest or response["request_id"] != request["request_id"]
        for response in responses
    ):
        raise ValueError("Partial response for a different request.")
    if len({response["trustee_id"] for response in responses}) != len(responses):
        raise ValueError("Duplicate trustee responses.")
    totals = {}
    for i, candidate in enumerate(public["candidate_ids"]):
        parts = [response["partials"][i] for response in responses]
        if any(part["id"] != response["trustee_id"] for part, response in zip(parts, responses)):
            raise ValueError("Trustee identity mismatch.")
        totals[str(candidate)] = combine_partials(
            public["paillier"], request["aggregates"][i], parts, digest + ":" + str(candidate)
        )
    if sum(totals.values()) != len(request["ballots"]):
        raise ValueError("Final tally count mismatch.")
    result = {
        "election_id": public["election_id"],
        "request_id": request["request_id"],
        "counts": totals,
        "ballots": len(request["ballots"]),
    }
    result["signature"] = rsa_sign(keys["rsa"]["private"], canonical(result))
    save_json(folder / "final_tally.json", result)
    audit(
        folder,
        "final_tally_decrypted",
        {"ballots": len(request["ballots"])},
        keys["rsa"]["private"],
    )
    return totals


def server_role_menu(folder, public, keys, state, role):
    """Input: authenticated admin/auditor session. Manage registration, listening, search and closed-election tally.
    Output: stored encrypted ballots, indexed IDs, tally-request files and final aggregate counts.
    """
    while True:
        print(
            "\nRole:",
            role,
            "Candidates:",
            public["candidate_ids"],
            "Accepted:",
            len(state["ballots"]),
            "Closed:",
            state["closed"],
        )
        if role == "admin":
            print(
                "1 Register voter  2 Listen for client requests  3 CLOSE voting  4 Export tally request  5 Combine trustee replies"
            )
        print("6 Search constituency  7 Search time range  8 Inspect encrypted ballots  0 Logout")
        try:
            choice = ask_text("Role choice")
            if choice == "0":
                return
            if role == "admin" and choice == "1":
                voter_id = ask_text("New voter ID")
                password = getpass.getpass("Password to protect voter credential: ")
                print(
                    "Deliver this credential privately:",
                    register_voter(folder, public, keys, state, role, voter_id, password),
                )
            elif role == "admin" and choice == "2":
                host = ask_text("Bind host", "127.0.0.1")
                port = ask_int("Port", 6044, 1024, 65535)
                count = ask_int("Connections (2 per normal vote)", 2, 1, 1000)
                serve_votes(folder, public, keys, state, role, host, port, count)
            elif role == "admin" and choice == "3":
                if ask_text("Close election to further votes? type CLOSE", "cancel") == "CLOSE":
                    close_election(folder, public, keys, state, role)
            elif role == "admin" and choice == "4":
                print(
                    "Give this request to at least two trustees:",
                    export_tally(folder, public, keys, state, role),
                )
            elif role == "admin" and choice == "5":
                paths = [
                    text.strip()
                    for text in ask_text("Partial-response paths, comma separated").split(",")
                ]
                print(
                    "Final candidate counts:",
                    finalize_tally(folder, public, keys, state, role, paths),
                )
            elif choice == "6":
                print(
                    "Matching ballot IDs:",
                    search_constituency(public, keys, state, role, ask_text("Constituency")),
                )
            elif choice == "7":
                start = float(ask_text("Start Unix seconds", public["starts_at"]))
                end = float(ask_text("End Unix seconds", public["ends_at"]))
                print(
                    "Matching ballot IDs:", search_time_range(public, keys, state, role, start, end)
                )
            elif choice == "8":
                print(json.dumps(state["ballots"], indent=2))
                print("Audit verified:", verify_audit(folder, keys["rsa"]["public"]))
            else:
                print("Option not permitted for this role.")
        except (ValueError, KeyError, TypeError, PermissionError, OSError) as error:
            print("Rejected:", error)
            audit(
                folder,
                "admin_operation_rejected",
                {"role": role, "reason": str(error)},
                keys["rsa"]["private"],
            )


def main():
    """Input: first-run election window, role passwords and authenticated admin/auditor menu choices.
    Output: initialized RSA-4096 election server and role-based operations. Start before the voter client.
    """
    folder = Path(__file__).resolve().parent / "storage"
    duration = (
        ask_int("First-run voting window minutes", 60, 1, 1440)
        if not (folder / "server_keys.json").exists()
        else 60
    )
    public, keys, state = initialize_election(folder, duration)
    accounts = setup_accounts(folder / "accounts.json", ("admin", "auditor"))
    while True:
        print("\n1 Login  0 Exit")
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice == "1":
                username, role = login(accounts)
                server_role_menu(folder, public, keys, state, role)
            else:
                print("Choose 1 or 0.")
        except (ValueError, PermissionError, OSError) as error:
            print("Rejected:", error)


if __name__ == "__main__":
    main()
