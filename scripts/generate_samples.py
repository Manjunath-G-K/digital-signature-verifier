"""Regenerate the files in sample_files/.

A throw-away key pair is created, the sample document is signed, and the
private key is discarded WITHOUT being written to disk. Only the public key,
the signature, the document and a one-bit-modified copy are saved.

Run from the project root:  python scripts/generate_samples.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import crypto_utils as cu  # noqa: E402

SAMPLE_TEXT = (
    "SAMPLE DOCUMENT - Digital Signature Verification System\n"
    "\n"
    "This is a sample document used for demonstrating RSA-PSS / SHA-256 signatures.\n"
    "Amount payable: 1000\n"
)


def main() -> None:
    out = ROOT / "sample_files"
    out.mkdir(exist_ok=True)

    document = SAMPLE_TEXT.encode("utf-8")
    private_key, public_key = cu.generate_key_pair()
    signature = cu.sign_document(document, private_key)
    del private_key  # never saved: nobody can create further signatures for this key

    # newline='' semantics: write raw bytes so the signed bytes are exactly what is on disk
    (out / "sample_document.txt").write_bytes(document)
    (out / "sample_document.txt.sig").write_bytes(signature)
    (out / "sample_public_key.pem").write_bytes(cu.public_key_to_pem(public_key))
    (out / "sample_document_tampered.txt").write_bytes(cu.flip_one_bit(document, len(document) - 3))
    print("Sample files written to", out)


if __name__ == "__main__":
    main()
