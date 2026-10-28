# Information Security endsem study pack

The workspace contains the lab-question solutions, the five previous-year-question solutions, reusable exam skeletons, and the original source material.

| Folder | Contents | Start here |
| --- | --- | --- |
| `Labs/` | Labs 1–8: 52 question/walkthrough folders, 57 Python files, and detailed Markdown/plain-text explanations | [Lab guide](Labs/README.md), [InfoSec basics](Labs/START_HERE.md), [question coverage](Labs/COVERAGE.md) |
| `PYQ_Solutions/` | Five PYQ solution folders, nine Python files, and detailed explanations for each question | [PYQ guide](PYQ_Solutions/README.md) |
| `skeleton/` | Skeletons 1–4: local/socket/role-based workflows, including Paillier totals and keyword search, with separate .txt storage | [Skeleton guide](skeleton/README.md) |
| `PYQ/` | Original questions | [Question text](PYQ/pyq.txt) |
| `docs/` | Three original lab-manual PDFs covering Labs 1–8 | [Source-material guide](docs/README.md) |
| `.venv/` | Local Python environment | Use `.venv/bin/python` for the commands below |

## Run a program

From this project folder, install the lab/PYQ dependency if needed:

```bash
.venv/bin/python -m pip install -r Labs/requirements.txt
```

Run a lab solution:

```bash
.venv/bin/python Labs/Lab_01/Q01_Additive_Multiplicative_Affine/solution.py
```

Run a PYQ solution:

```bash
.venv/bin/python PYQ_Solutions/Q01_RSA_Box_Cost/solution.py
```

Read the explanation beside each program for its menu, inputs, file setup and any client/server startup order. Programs use functions and library APIs without user-defined classes. Some lab exercises need external GnuPG or Snort executables; their individual explanations describe setup and limits.

## Study order

Read the InfoSec basics, practice the relevant lab concept, then open the matching PYQ solution. Every question has both explanation.md and explanation.txt. The question-specific programs provide reusable functions within each file.

## Verification records

[Lab validation](Labs/VALIDATION.md) and [PYQ validation](PYQ_Solutions/VALIDATION.md) describe previously performed program checks and their limitations. Documentation was reviewed on 29 October 2026: folder counts, coverage paths and local Markdown links match the current workspace. This documentation review does not constitute a new run of the cryptographic programs.

## Adapting a skeleton

The [replacement guides](skeleton/Replacement_Guide/README.md) explain exact edits for each skeleton, with tested algorithm recipes and lab references. Markdown and plain-text versions are provided.
