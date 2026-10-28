# Information Security lab code pack

This pack covers the main and additional exercises in the three supplied manuals, Labs 1–8. The original PYQ file is preserved in `../PYQ/pyq.txt`; solutions to all five questions are in [PYQ_Solutions](../PYQ_Solutions/README.md). Each question is standalone: copy its folder, install the dependency, and run its Python file. No user-defined classes or object-oriented architecture are used. Library APIs such as AES.new return cipher objects; calling those APIs is normal library use, not a requirement to learn classes.

## Setup

Open a terminal in the project root (the folder containing Labs):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r Labs/requirements.txt
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.

Run any question from the project root, for example:

```bash
.venv/bin/python Labs/Lab_01/Q01_Additive_Multiplicative_Affine/solution.py
```

From inside a question folder, the environment Python is `../../../.venv/bin/python`.

Programs have menus. Choose 1 to run, then enter inputs. Press Enter to use a displayed example value. Choose 0 to go back or exit. Scenarios such as key management/search have their own operation menu inside the outer Run menu. Generated storage, ciphertexts, keys and benchmark outputs are kept beside their script, not in the folder where your terminal happens to be.

For client/server questions, read that folder's explanation first: run the server and client in separate terminals. Lab 6 signature exchange needs one client setup run before the server starts, so its public-key file can be trusted.

GnuPG and Snort require external executables (`gpg` and `snort`), not additional Python packages. The Snort exercise can generate its sample capture and rule even when Snort is absent.

## Where to start if InfoSec is new

Read `START_HERE.md`, then pick a question and read its explanation while following `exercise()` in the code. Every function documents its inputs, operation, outputs and usage. A main/interactive function gets inputs and calls smaller algorithm functions. You can reuse those functions in a new scenario without rewriting the cryptography.

## Coverage

- [Lab 1: Basic symmetric key ciphers](Lab_01/README.md): 9 question/walkthrough folders
- [Lab 2: Advanced symmetric key ciphers](Lab_02/README.md): 10 question/walkthrough folders
- [Lab 3: Asymmetric key ciphers](Lab_03/README.md): 10 question/walkthrough folders
- [Lab 4: Advanced asymmetric cryptography](Lab_04/README.md): 4 question/walkthrough folders
- [Lab 5: Hashing](Lab_05/README.md): 4 question/walkthrough folders
- [Lab 6: Digital signatures](Lab_06/README.md): 5 question/walkthrough folders
- [Lab 7: Partial homomorphic encryption](Lab_07/README.md): 6 question/walkthrough folders
- [Lab 8: Searchable encryption](Lab_08/README.md): 4 question/walkthrough folders

[COVERAGE.md](COVERAGE.md) lists all 52 question/walkthrough folders and important corrections to the manuals. These folders contain 57 Python files, with detailed Markdown and plain-text explanations for each question. The standalone RSA signature walkthrough is included as Lab 6 Q00 in addition to the numbered questions.

## Important distinctions in these manuals

- A hash is a one-way digest, not encryption; it cannot be decrypted.
- Digital signatures use private keys to sign and public keys to verify. Never exchange private keys as the signature walkthrough suggests.
- Diffie–Hellman agrees on a secret; it does not sign messages. Its Lab 6 exercise explains HMAC authentication separately.
- A 32-hex-character AES key is 16 bytes. Prefix input keys with hex: or text: where requested. Some manual keys have invalid lengths or degenerate Triple DES components; individual explanations show corrections.
- Ordinary ElGamal supports multiplication, not a general encrypted greater-than comparison.
- Raw textbook RSA has multiplicative homomorphism. RSA-OAEP does not preserve that property.
- Correct Paillier arithmetic uses modulus n squared for ciphertexts. The manual's sample is not a correct Paillier implementation.
- Fresh randomized AES/RSA/Paillier ciphertexts do not form stable equality-search keys. Search exercises use explicit HMAC tokens and describe what that assumes/leaks.
- The threshold exercise reconstructs a Shamir-shared private exponent in one process. It demonstrates threshold-controlled decryption, not a fully distributed threshold-Paillier protocol.
- Summing arbitrary candidate IDs does not produce per-candidate election counts. The [e-voting PYQ solution](../PYQ_Solutions/Q04_E_Voting/explanation.md) uses per-candidate encrypted counters and explains its vote encoding.

These are teaching programs. Some print intermediate values or use deliberately small finite-field parameters to make the mathematics fast and visible. Their explanations identify those choices. Persistent local role simulations trust the OS account; they do not claim to implement authenticated production services or regulatory compliance.
