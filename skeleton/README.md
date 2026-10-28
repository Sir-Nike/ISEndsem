# Exam skeletons

[Skeleton 1](Skeleton_1/explanation.md) implements setup, input, AES-256-GCM encryption, RSA-OAEP key wrapping, ElGamal signatures, SHA-256 hashes, separate .txt storage, public verification and authenticated decryption. Each function documents its inputs, operation, output and usage; explanation.txt accompanies the Markdown guide.

Run from the project root:

```bash
.venv/bin/python -m pip install -r skeleton/requirements.txt
.venv/bin/python skeleton/Skeleton_1/skeleton.py
```

Choose 1 for identity setup, 2 to send/save, 3 to verify, and 4 to receive/decrypt. The ElGamal group defaults to 256-bit lab practice parameters; see the explanation before choosing the required exam size. Keep the trusted key files and all private files separate from the transmitted outbox.

## Skeleton 2: simple socket client/server

[Skeleton 2 explanation](Skeleton_2/explanation.md) covers plain TCP sockets, compact role login menus, permission/ownership checks, separate .txt record storage, logging, signed audit and practice-copy tampering. Signing/encryption and receiver decryption stay on the clients.

Keep server.py, client.py and crypto_helpers.py together. Use two terminals:

```bash
.venv/bin/python skeleton/Skeleton_2/server.py
.venv/bin/python skeleton/Skeleton_2/client.py
```

The server asks for the admin login password only on first use, then starts automatically. Log into the client as admin to create users. Have the receiver log in once before the sender submits. The explanation includes all menus and a worked run. Uses PyCryptodome only; all runtime files are .txt.

## Skeleton 3: one local role-based program

[Skeleton 3 explanation](Skeleton_3/explanation.md) covers the same message cryptography with local sender/reviewer/receiver/admin login, persistent multi-record .txt storage, role/ownership checks, operational logging, signed audit, and practice-copy tampering. No sockets or client/server modules are involved. A matching explanation.txt includes the worked run and every function's contract.

```bash
.venv/bin/python skeleton/Skeleton_3/skeleton.py
```

First run asks for an admin password. Log in as admin to create users. Have the receiver log in once to generate/register its key, then the sender can save addressed messages. All application logic and algorithms are in the one skeleton.py file.

## Skeleton 4: local records with Paillier and keyword search

[Skeleton 4 explanation](Skeleton_4/explanation.md) extends Skeleton 3 with Paillier amounts/totals, HMAC keyword indexing, a finance role, and explicit Search by keyword actions for reviewer/receiver/finance. It retains local login/permissions, AES/RSA/ElGamal/SHA-256, separate .txt storage, logs, signed audit and tamper-copy checks. All code is in one skeleton.py; no sockets or hidden password prompts. A matching explanation.txt includes the entire workflow, worked run, storage layout and every function.

```bash
.venv/bin/python -m pip install -r skeleton/Skeleton_4/requirements.txt
.venv/bin/python skeleton/Skeleton_4/skeleton.py
```

Uses PyCryptodome plus phe for library-based Paillier. First run initializes its own admin/key/data state. Create users and let the receiver register before saving records. Search returns permitted metadata with no decryption; finance decrypts only the calculated aggregate.
