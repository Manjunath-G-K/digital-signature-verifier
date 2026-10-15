# Digital Signature Verification System

A CNS (Cryptography and Network Security) mini-project that shows how a **digital signature** proves a document has not been altered and was signed with a particular private key. It uses **RSA-PSS with SHA-256** through Python's `cryptography` library, with a **Streamlit** user interface.

## Features

- **Generate Keys** – RSA 2048-bit key pair, downloadable as PEM files (the private key is never shown on screen).
- **Sign a Document** – upload any file plus a private key (or generate a new pair); download the signature as a separate `.sig` file. The document is never modified.
- **Verify a Signature** – upload document + signature + public key; get a clear **VALID** or **INVALID**. Unreadable inputs (malformed key, empty/oversized files) are reported as *"Cannot be processed"*, never as VALID.
- **Tampering Demonstration** – live demo with no files needed, plus a tool that flips one bit of a real file.
- **About the Cryptographic Algorithms** – RSA, SHA-256, PSS, key roles, encryption vs. signatures, and what a signature does *not* prove.

### Cryptographic parameters

| Item | Value |
|---|---|
| Key type / size | RSA, 2048 bits (smaller keys are rejected), e = 65537 |
| Signature scheme | RSA-PSS |
| Hash | SHA-256 |
| Mask generation | MGF1 with SHA-256 |
| Salt length | `PSS.MAX_LENGTH` (used for both signing and verifying) |
| Signed data | The raw bytes of the uploaded file |
| Key format | PKCS#8 PEM (private, unencrypted), SubjectPublicKeyInfo PEM (public) |
| Signature format | Raw binary (256 bytes for a 2048-bit key) |

## Prerequisites

- Windows 10/11 (the commands also work on macOS/Linux with minor changes)
- Python 3.10 or newer – check with `python --version`

## Installation (Windows, PowerShell)

```powershell
cd path\to\project            # the folder containing app.py
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell refuses to run the activation script, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Using **Command Prompt** instead? Activate with `.venv\Scripts\activate.bat`.

## Run the application

```powershell
streamlit run app.py
```

Your browser opens at <http://localhost:8501>. Press `Ctrl+C` in the terminal to stop.

## Run the tests

```powershell
python -m pytest -v
```

`tests/test_crypto_utils.py` tests the cryptographic module; `tests/test_app_smoke.py` checks that every page renders and that the live tampering demo flips from VALID to INVALID.

## Project structure

```
.
├── app.py                 Streamlit UI (no cryptography here)
├── crypto_utils.py        All cryptographic operations
├── requirements.txt
├── pytest.ini
├── README.md
├── docs/project_report.md College project report (fill in the placeholders)
├── sample_files/          Sample document, signature, public key, tampered copy
├── scripts/generate_samples.py  Regenerates sample_files (discards the private key)
└── tests/
```

## Step-by-step demonstration (for evaluation)

### A. Sign and verify a document

1. Open **Generate Keys** → click *Generate new 2048-bit RSA key pair* → download `private_key.pem` and `public_key.pem`. Point out the confidentiality warning.
2. Open **Sign a Document** → upload any file (e.g. a `.txt` or `.pdf`) → choose *Upload an existing private key* and upload `private_key.pem` → click **Sign document** → download the `.sig` file.
3. Open **Verify a Signature** → upload the **same document**, the `.sig` file and `public_key.pem` → click **Verify signature** → result: **VALID**.

### B. Demonstrate tampering

1. Open **Tampering Demonstration** → click *Sign this text with a temporary demo key* → the received copy shows **VALID**.
2. Click **Change one character** (or edit the text yourself) → result flips to **INVALID**, and the SHA-256 hashes shown are completely different. Click **Restore original** → **VALID** again.
3. File version: in *Part 2* upload the document from workflow A, download the tampered copy, then verify it on **Verify a Signature** with the original `.sig` and public key → **INVALID**.

### C. Failure handling to show the evaluators

- Verify with a **different** public key (generate a second pair) → INVALID.
- Upload the **private** key where the public key is expected → "looks like a PRIVATE key" message (nothing is verified).
- Upload a random text file as the public key or signature → "Cannot be processed" (this is not an INVALID result).

### D. Ready-made sample files

`sample_files/` contains `sample_document.txt`, `sample_document.txt.sig`, `sample_public_key.pem` and `sample_document_tampered.txt`. Verifying the original gives VALID; verifying the tampered copy with the same signature gives INVALID. The private key for this sample was discarded and is not stored anywhere. These files are also downloadable from the app's Home and Tampering pages. Do not edit the sample document in an editor that changes line endings or adds a final newline – that would (correctly) make it INVALID. Regenerate everything with `python scripts/generate_samples.py` if needed.

## Security notes and limitations

- **A valid signature proves integrity and possession of the private key. It does not prove the real-world identity of the signer.** Binding a public key to a person or organisation needs a trust mechanism (e.g. a certificate authority or a trusted exchange of keys), which is outside this project.
- Private keys are downloaded **unencrypted**. Anyone who obtains the file can sign as you. Store it in a protected folder, never share or commit it (`.gitignore` blocks `*.pem` except the sample public key), and generate a new pair if it may have leaked. Password-protected PEM keys are not supported.
- Keys generated in the app are held in server memory for the browser session so the download buttons keep working; closing the tab/stopping the server discards them. Run the app locally – do not deploy it publicly for real keys.
- A temporary demo key in the Tampering page is discarded right after signing.
- Documents are limited to 10 MB. Empty documents are refused for both signing and verification.
- No timestamping, revocation, certificates or multiple-signer support – by design, to keep the project focused.
- This is an educational project, not a certified signing product.
