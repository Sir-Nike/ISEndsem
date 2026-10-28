from crypto_helpers import *


def make_partial_response(public, request, credential):
    """Input: trusted public config, closed-election tally request and ONE trustee credential.
    Output: verifiable partial responses for final candidate aggregates only. No full private key is reconstructed.
    """
    validate_tally_request(public, request)
    if credential["election_id"] != public["election_id"]:
        raise ValueError("Trustee share belongs to another election.")
    share = credential["share"]
    if str(share["id"]) not in public["paillier"]["verification"]:
        raise ValueError("Unknown trustee share.")
    if (
        pow(
            public["paillier"]["v"],
            public["paillier"]["delta"] * share["secret"],
            public["paillier"]["n"] ** 2,
        )
        != public["paillier"]["verification"][str(share["id"])]
    ):
        raise ValueError("Trustee share was modified.")
    digest = hashlib.sha256(canonical(request)).hexdigest()
    parts = [
        partial_decrypt(public["paillier"], share, ciphertext, digest + ":" + str(candidate))
        for candidate, ciphertext in zip(public["candidate_ids"], request["aggregates"])
    ]
    return {
        "election_id": public["election_id"],
        "request_id": request["request_id"],
        "request_hash": digest,
        "trustee_id": share["id"],
        "partials": parts,
    }


def main():
    """Input: trustee menu, trusted config, signed tally request and a single private share file.
    Output: partial-response JSON file for the admin to combine with another trustee's response.
    """
    folder = Path(__file__).resolve().parent
    while True:
        print("\n1 Verify final request and produce ONE trustee response  0 Exit")
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice != "1":
                print("Choose 1 or 0.")
                continue
            public = read_json(
                Path(
                    ask_text(
                        "Trusted public config", str(folder / "storage" / "public_config.json")
                    )
                )
            )
            request = read_json(
                Path(
                    ask_text("Signed tally request", str(folder / "storage" / "tally_request.json"))
                )
            )
            credential = read_json(Path(ask_text("Your ONE trustee share file")))
            response = make_partial_response(public, request, credential)
            path = Path(
                ask_text(
                    "Save response path",
                    str(folder / "partials" / f'trustee_{response["trustee_id"]}.json'),
                )
            )
            save_json(path, response)
            print(
                "Partial response saved:",
                path,
                "No individual votes or private shares were decrypted/reconstructed.",
            )
        except (ValueError, KeyError, TypeError, OSError) as error:
            print("Rejected:", error)


if __name__ == "__main__":
    main()
