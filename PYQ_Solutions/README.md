# PYQ solutions: Information Security lab

Five standalone question folders implement the five questions in `PYQ/pyq.txt`. Each has function-based Python with input/operation/output/usage docstrings, an interactive menu, and detailed explanations in Markdown and plain text. There are no user-defined classes and no special command-line execution mode.

The current pack has five question folders, nine Python files, and an explanation.md / explanation.txt pair for every question. See the [workspace guide](../README.md) for the full folder layout.

## Open the question explanations

- [Q1: RSA encrypted box-cost multiplication](Q01_RSA_Box_Cost/explanation.md)
- [Q2: Patient records, AES, SHA-256, RSA and Paillier](Q02_Patient_Records/explanation.md)
- [Q3: Secure grant expense portal](Q03_Grant_Expense_Portal/explanation.md)
- [Q4: Encrypted e-voting with client/server and threshold tally](Q04_E_Voting/explanation.md)
- [Q5: Expiring-key report management with HMAC search and audit](Q05_Report_Management/explanation.md)

## Setup and run

From the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r PYQ_Solutions/requirements.txt
.venv/bin/python PYQ_Solutions/Q01_RSA_Box_Cost/solution.py
```

The existing workspace environment already has PyCryptodome. On Windows substitute `.venv\Scripts\python.exe` for the environment Python path. Inside a question folder use `../../.venv/bin/python solution.py`.

Q1 takes all RSA and box/cost values from prompts. Q2 starts with option 10 to enter the exam dataset, then 2 to encrypt and 4 to sign. Q3/Q5 ask you to set local role passwords on first use. Q4 uses separate server/client terminals and a trustee utility; follow its worked-run instructions before starting. Its `crypto_helpers.py` must stay beside its programs.

## Study in this order

1. Read the question's plain-English idea and worked run.
2. Run the menu, following that worked run.
3. Read the menu code, then the functions it calls; look for inputs, bytes/dictionaries and printed outputs.
4. Repeat with a wrong ID, altered data or an unauthorized role and understand why access is rejected.
5. Use Q4's advanced proofs only after understanding AES, hashes, signatures, Paillier sums and the one-hot tally.

The explanations preserve the original questions, map each operation to functions, explain every function, provide complete walkthroughs and identify assumptions/corrections. Q2's actual supplied exam dataset is missing from the source file; its example rows are explicitly illustrative and editable. Q4 resolves ambiguous ID-summing and hash-verification/privacy requirements explicitly. Q5 explains why external-key tampering fails the signed key-binding check even when unchanged record bytes still have a valid RSA signature.

The original questions remain in `PYQ/pyq.txt`. The [Labs pack](../Labs/README.md) contains the separate solutions for Labs 1–8; this folder contains the five question-specific PYQ solutions. Generated practice state stays inside each question folder. See `VALIDATION.md` for the checks performed. These are lab teaching programs, with small practice finite-field parameters where documented; the voting example is not a production election system.
