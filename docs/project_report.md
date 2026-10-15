<div align="center">

# DIGITAL SIGNATURE VERIFICATION SYSTEM

### A Mini-Project Report on Cryptography and Network Security

Submitted in partial fulfilment of the requirements of the course
**Cryptography and Network Security**

---

**Submitted by**

| Student Name | USN |
|---|---|
| `[STUDENT 1 NAME]` | `[USN]` |
| `[STUDENT 2 NAME]` | `[USN]` |
| `[STUDENT 3 NAME]` | `[USN]` |

**Under the guidance of:** `[FACULTY NAME, DESIGNATION]`

**Department of** `[DEPARTMENT NAME]`
`[COLLEGE NAME]`, `[CITY]`
**Semester:** `[SEMESTER]` &nbsp;&nbsp; **Academic Year:** `[20XX – 20XX]`

</div>

> **Note to students:** every item written as `[LIKE THIS]` is a placeholder you must fill in yourself. Nothing in this template states institutional details, screenshots or references that have not been supplied.

---

## Table of Contents

1. Abstract
2. Introduction
3. Problem Statement
4. Objectives
5. Existing System and Proposed System
6. Software and Hardware Requirements
7. System Architecture
8. Module Descriptions
9. Algorithms and Working Principles
10. Implementation Details
11. Testing Methodology and Results
12. Sample Execution Results and Screenshots
13. Advantages and Limitations
14. Applications
15. Conclusion
16. References

---

## 1. Abstract

Documents exchanged electronically can be altered without leaving visible traces, and a recipient often cannot tell whether a file is the one its sender produced. This project implements a *Digital Signature Verification System* that demonstrates how public-key cryptography addresses this problem. A user generates an RSA key pair, signs a document with the private key using the RSA-PSS scheme with SHA-256, and anyone holding the matching public key can verify that the document is unchanged and that the signature was produced by the corresponding private key. The system is written in Python, uses the `cryptography` library for all cryptographic primitives and Streamlit for a browser-based interface. It includes a tampering demonstration showing that modifying a single byte of a signed document makes verification fail. The system is covered by 59 automated tests (49 on the cryptographic module, 10 on the user interface), all of which passed in the final run reported in Section 11.

## 2. Introduction

Cryptography and Network Security addresses confidentiality, integrity, authentication and non-repudiation. Encryption primarily provides confidentiality, whereas a **digital signature** primarily provides integrity and authentication of the key holder. A digital signature is computed from the document and the signer's private key; it can be checked by anyone using the signer's public key, but it cannot practically be forged without the private key.

This project builds a small, easy-to-demonstrate application around that idea. It is deliberately limited to one algorithm family (RSA with PSS padding and SHA-256) so that its behaviour can be explained completely during evaluation.

## 3. Problem Statement

To design and implement a simple, correct and demonstrable application that lets a user sign an arbitrary document with a private key and lets another party verify, using only the public key, whether a document and signature pair is genuine, clearly distinguishing a *failed verification* from an *input that could not be processed*, and demonstrating that any modification of the document is detected.

## 4. Objectives

1. Generate RSA key pairs of at least 2048 bits and export them as PEM files.
2. Sign arbitrary files with RSA-PSS (SHA-256, MGF1-SHA256) and store the signature as a separate file without altering the original.
3. Verify a document, signature and public key and report a clear VALID or INVALID result.
4. Handle malformed keys, corrupted signatures, empty files and wrong keys gracefully.
5. Demonstrate that changing even one byte of a signed document causes verification to fail.
6. Provide educational explanations of the underlying concepts, including the limits of what a signature proves.
7. Verify the implementation with an automated test suite.

## 5. Existing System and Proposed System

### 5.1 Existing system

Without signatures, integrity of a transferred file is typically judged by file name, file size, a visible "from" line, or a plain checksum published alongside the file. A plain checksum (for example an unkeyed SHA-256 hash) detects accidental corruption, but an attacker who can modify the file can also replace the checksum, so it provides no authentication. Manual verification methods do not scale and are error-prone.

### 5.2 Proposed system

The proposed system binds a document to a private key through an RSA-PSS signature. Verification needs only the document, the signature file and the public key. A tampered document, a damaged signature, or a signature from a different key all fail verification. The system presents results in a simple web interface and keeps all cryptographic code in a separate, tested module.

## 6. Software and Hardware Requirements

### 6.1 Software

| Component | Details |
|---|---|
| Operating system | Windows 11 (development and testing environment used here); any OS supporting Python 3 should work |
| Language | Python 3 (tested with Python 3.13.7) |
| Libraries | `cryptography` (tested with 46.0.5), `streamlit` (tested with 1.61.1), `pytest` (tested with 9.0.2) |
| Browser | Any modern web browser |

### 6.2 Hardware

No special hardware is required. A standard computer able to run a modern web browser and Python is sufficient. `[ADD YOUR OWN MACHINE DETAILS: processor, RAM]`

## 7. System Architecture

The application has two layers. The user interface contains no cryptographic code; it only collects inputs, calls `crypto_utils.py` and displays results.

```
+-------------------------------------------------------------+
|                    Browser (user)                           |
+------------------------------+------------------------------+
                               |  HTTP (localhost)
+------------------------------v------------------------------+
|  app.py  -  Streamlit user interface                        |
|  Home | Generate Keys | Sign | Verify | Tamper | About       |
+------------------------------+------------------------------+
                               |  function calls
+------------------------------v------------------------------+
|  crypto_utils.py  -  cryptographic logic and validation     |
|  key generation | PEM load/save | sign | verify | helpers   |
+------------------------------+------------------------------+
                               |
+------------------------------v------------------------------+
|  Python `cryptography` library (RSA, PSS, MGF1, SHA-256)    |
+-------------------------------------------------------------+
```

Data flow:

```
SIGNING
 document bytes ---> SHA-256 ---> PSS encode (salt, MGF1) ---> RSA private-key op ---> signature file

VERIFICATION
 document bytes + signature + public key ---> RSA-PSS verify (SHA-256) ---> VALID / INVALID
                                  \--> unreadable input ---> "cannot be processed" (no verdict)
```

There is no database, backend server or network service beyond the local Streamlit server. Uploaded files are held in memory for the duration of a request and are not written to disk by the application.

## 8. Module Descriptions

### 8.1 `crypto_utils.py` – cryptographic module

| Function | Purpose |
|---|---|
| `generate_key_pair()` | Generates an RSA key pair (2048 bits by default; sizes under 2048 are refused). |
| `private_key_to_pem()`, `public_key_to_pem()` | Serialise keys (PKCS#8 and SubjectPublicKeyInfo PEM). |
| `load_private_key()`, `load_public_key()` | Parse PEM input; reject empty, malformed, encrypted, non-RSA or weak keys with clear messages. |
| `public_key_fingerprint()` | SHA-256 of the DER public key, to compare keys visually. |
| `validate_document()` | Rejects empty documents and documents over 10 MB. |
| `sign_document()` | Signs raw document bytes with RSA-PSS / SHA-256. |
| `verify_signature()` | Returns `True` only for a valid signature, `False` for any non-matching signature, and raises an input error for unprocessable input. |
| `flip_one_bit()` | Produces a one-bit-modified copy for the tampering demonstration. |
| `sha256_hex()` | Hex digest used for display only. |

Custom exceptions (`KeyLoadError`, `DocumentError`, `SignatureFormatError`, all subclasses of `CryptoInputError`) separate *unprocessable input* from an *invalid signature*.

### 8.2 `app.py` – user interface

Six pages selected from a sidebar: Home / Project Overview, Generate Keys, Sign a Document, Verify a Signature, Tampering Demonstration, About the Cryptographic Algorithms. The private key is offered only as a download and is never printed on screen.

### 8.3 `tests/` – automated tests

`test_crypto_utils.py` tests the cryptographic module directly; `test_app_smoke.py` uses Streamlit's `AppTest` to run every page and the live tampering demo.

### 8.4 `scripts/generate_samples.py` and `sample_files/`

Creates the sample document, its signature, the public key and a tampered copy. The throw-away private key is discarded without being written to disk.

## 9. Algorithms and Working Principles

### 9.1 RSA

RSA is an asymmetric algorithm. Two large primes *p* and *q* give the modulus *n = p·q*. A public exponent *e* (here 65537) and a private exponent *d* satisfy *e·d ≡ 1 (mod φ(n))*. A private-key operation on a value *m* is *m^d mod n*, and the public key undoes it with *e*. Security relies on the difficulty of factoring *n* when it is large (2048 bits here).

### 9.2 SHA-256

SHA-256 maps input of any length to a 256-bit digest. It is deterministic and designed to be preimage-resistant and collision-resistant. A one-bit change of input changes the digest unpredictably (avalanche effect), which is what makes tampering detectable.

### 9.3 RSA-PSS

Raw ("textbook") RSA signing is unsafe. PSS (Probabilistic Signature Scheme) encodes the message digest together with a random salt using a mask generation function before the RSA operation. This project uses:

- Hash: SHA-256
- MGF1 with SHA-256
- Salt length: `PSS.MAX_LENGTH`, the same configuration for signing and verification (defined once in `_pss_padding()`).

Because the salt is random, signing the same document twice produces different signatures; both verify successfully. (This is tested.)

### 9.4 Signing and verification

1. **Sign:** the library hashes the document bytes with SHA-256, applies PSS encoding, and performs the RSA private-key operation. The result (256 bytes for a 2048-bit key) is saved as the signature file.
2. **Verify:** the library applies the RSA public-key operation to the signature, decodes the PSS structure, recomputes the SHA-256 digest of the received document and checks that they match. A mismatch raises `InvalidSignature`, which the application reports as **INVALID**.

### 9.5 Encryption versus digital signature

| | Encryption | Digital signature |
|---|---|---|
| Goal | Confidentiality | Integrity and key-holder authentication |
| Protected with | Recipient's public key | Signer's private key |
| Checked / undone with | Recipient's private key | Signer's public key |
| Content hidden? | Yes | No – the document stays readable |

### 9.6 What a valid signature does and does not prove

A VALID result shows that the document bytes are identical to the signed bytes and that the signature was created with the private key matching the supplied public key. It does **not** by itself establish who owns that key in the real world; that needs a trusted way of binding public keys to identities (for example certificates issued by a certificate authority, or exchanging the key over a trusted channel), which is outside the scope of this project.

## 10. Implementation Details

- **Language and libraries:** Python 3; `cryptography` (hazmat `rsa`, `padding`, `hashes`, `serialization`); Streamlit; pytest. No cryptographic primitive is implemented manually.
- **Key generation:** `rsa.generate_private_key(public_exponent=65537, key_size=2048)`.
- **Signing:** `private_key.sign(data, PSS(mgf=MGF1(SHA256), salt_length=PSS.MAX_LENGTH), SHA256)` on the raw uploaded bytes (file names and displayed text are never signed).
- **Verification:** `public_key.verify(signature, data, <same padding>, SHA256)`; `InvalidSignature` → `False`.
- **Input validation:** empty documents are refused for both signing and verification; documents over 10 MB are refused; empty or implausibly large signature files are refused; keys must be RSA and at least 2048 bits; encrypted private keys are rejected with an explanatory message.
- **Result semantics:** three outcomes are kept apart in the interface – ✅ VALID, ❌ INVALID, and ⚠️ *cannot be processed* (no verdict).
- **Key handling:** PEM private keys are shown only as a download button, never rendered or logged. Error messages never include key contents. Generated keys are kept in the server's session memory only so that the download buttons keep working.
- **Tampering helper:** `flip_one_bit()` flips the lowest bit of a chosen byte and returns a new copy.

## 11. Testing Methodology and Results

### 11.1 Methodology

Tests were written with pytest and cover the cryptographic module directly and the user interface through Streamlit's `AppTest`. Failure cases check that nothing is reported as valid when it should not be. A cross-check verifies a signature with raw `cryptography` calls using the documented parameters, so the test does not depend on the project's own wrapper.

### 11.2 Test coverage by category

| Category | What is checked |
|---|---|
| Key generation | RSA type, ≥ 2048 bits, unique pairs, weak sizes refused, PEM round-trip, fingerprint |
| Sign / verify | Successful verification, signature length, randomised signatures both valid, original document unmodified, independent PSS cross-check, binary data |
| Tampering | Appended data, replaced text, single-bit flip at start/middle/end, helper leaves original untouched, bad index rejected |
| Wrong key / bad signature | Different public key, corrupted, truncated, extended, random, and other-document signatures all fail |
| Malformed keys | Empty/garbage/truncated PEM, public key used as private key and vice versa, encrypted key, non-RSA (EC) keys, 1024-bit keys, no key material in error messages |
| Empty / invalid inputs | Empty document (sign and verify), oversized document, non-bytes input, empty and oversized signature file |
| File handling | Full file-based workflow on disk, file name irrelevance, SHA-256 known-answer test, shipped sample files behave as documented and no private key ships |
| User interface | Every page renders; private key not displayed; verify with no files never shows VALID; sign without a document shows an error; live demo goes VALID → INVALID → VALID |

### 11.3 Actual results

Command: `python -m pytest -q`
Environment: Windows 11, Python 3.13.7, pytest 9.0.2, cryptography 46.0.5, streamlit 1.61.1.

```
59 passed
```

49 tests are in `tests/test_crypto_utils.py` and 10 in `tests/test_app_smoke.py`. `[RE-RUN THE TESTS ON YOUR OWN MACHINE AND PASTE YOUR OUTPUT HERE, WITH DATE]`

### 11.4 Testing limitations

Streamlit's `AppTest` cannot drive the file-upload widgets, so the upload-and-click flow of the Sign and Verify pages was not exercised by automated tests; the underlying cryptographic functions those pages call are covered by the unit tests, and the pages are validated for the "missing input" paths. Run the manual walkthrough in the README (workflows A–D) to confirm the complete file-based flow in your own environment, and record the outcome in Section 12.

## 12. Sample Execution Results and Screenshots

The screenshots below must be captured by you while running the application (`streamlit run app.py`). Replace each placeholder with an image and record what you observed.

| # | Screenshot to capture | Image |
|---|---|---|
| 1 | Home page | `[INSERT SCREENSHOT]` |
| 2 | Generate Keys page after generating a pair (public key and fingerprint visible, private key not shown) | `[INSERT SCREENSHOT]` |
| 3 | Sign a Document page after signing, with the signature download button | `[INSERT SCREENSHOT]` |
| 4 | Verify a Signature – result **VALID** for the original document | `[INSERT SCREENSHOT]` |
| 5 | Verify a Signature – result **INVALID** for a tampered document | `[INSERT SCREENSHOT]` |
| 6 | Verify a Signature – wrong public key result | `[INSERT SCREENSHOT]` |
| 7 | Verify a Signature – malformed key file ("Cannot be processed") | `[INSERT SCREENSHOT]` |
| 8 | Tampering Demonstration – live demo before and after changing one character | `[INSERT SCREENSHOT]` |
| 9 | Terminal output of `python -m pytest -v` | `[INSERT SCREENSHOT]` |

**Sample files supplied with the project** (`sample_files/`): verifying `sample_document.txt` with `sample_document.txt.sig` and `sample_public_key.pem` is expected to give VALID, and verifying `sample_document_tampered.txt` with the same signature is expected to give INVALID. This behaviour is checked by an automated test. `[RECORD WHAT YOU OBSERVED IN THE APPLICATION]`

## 13. Advantages and Limitations

### Advantages

- Detects any change to the signed document, however small.
- Verification needs only the public key; the private key never has to be shared.
- Uses standard, well-reviewed primitives (RSA-PSS, SHA-256) from an established library.
- Simple interface with explicit VALID / INVALID / cannot-process outcomes.
- Cryptographic logic is separate from the interface and covered by automated tests.

### Limitations

- A valid signature does not establish the real-world identity of the signer; there are no certificates or certificate authority.
- Private keys are exported unencrypted; password-protected keys are not supported.
- No timestamps, revocation, multiple signers, or signature embedding inside documents (signatures are separate files).
- Documents are limited to 10 MB and processed in memory.
- The application is intended for local, educational use and is not a certified signing product.
- Only RSA-PSS with SHA-256 is supported.

## 14. Applications

The principle demonstrated here is used in software distribution (verifying installers and updates), signed contracts and electronic documents, secure e-mail signing, code signing, and the certificates used by HTTPS. Production systems add certificate authorities, trusted timestamps and hardware-protected keys, which this project does not implement.

## 15. Conclusion

The project implements the core of a digital signature workflow – key generation, signing with RSA-PSS and SHA-256, and verification – and shows how any modification to a document is detected. The design keeps cryptography in a tested module, separates failed verification from unprocessable input, and explains clearly what a valid signature does and does not prove. Possible extensions, outside the present scope, include password-protected private keys and linking public keys to identities through certificates. `[ADD YOUR OWN CONCLUSIONS AND LEARNING OUTCOMES]`

## 16. References

The following are the primary standards and documentation relevant to the techniques used. Verify each entry and add any further sources you actually consulted before submission.

1. RFC 8017 – *PKCS #1: RSA Cryptography Specifications Version 2.2* (defines RSASSA-PSS and MGF1), IETF.
2. NIST FIPS PUB 180-4 – *Secure Hash Standard (SHS)* (defines SHA-256).
3. NIST FIPS PUB 186-5 – *Digital Signature Standard (DSS)*.
4. Python `cryptography` library documentation – RSA asymmetric primitives, <https://cryptography.io>.
5. Streamlit documentation, <https://docs.streamlit.io>.
6. pytest documentation, <https://docs.pytest.org>.
7. `[ADD YOUR TEXTBOOK AND COURSE REFERENCES, e.g. author, title, edition, year]`
