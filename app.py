"""Digital Signature Verification System - Streamlit user interface.

All cryptography lives in crypto_utils.py; this file only handles the UI.
Run with:  streamlit run app.py
"""

from pathlib import Path

import streamlit as st

import crypto_utils as cu

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_files"

PAGES = [
    "Home / Project Overview",
    "Generate Keys",
    "Sign a Document",
    "Verify a Signature",
    "Tampering Demonstration",
    "About the Cryptographic Algorithms",
]

DEMO_TEXT = (
    "To whom it may concern,\n"
    "\n"
    "I authorise a payment of 1000 to Alice.\n"
    "\n"
    "Signed digitally.\n"
)

st.set_page_config(page_title="Digital Signature Verification System", page_icon="🔏", layout="centered")


# ---------------------------------------------------------------- shared widgets
def private_key_warning() -> None:
    st.warning(
        "**Keep your private key confidential.** Anyone who has it can create signatures that "
        "appear to come from you. Never share it, e-mail it or upload it to a site you do not "
        "trust. Only the public key may be shared."
    )


def show_hash(label: str, data: bytes) -> None:
    st.caption(label)
    st.code(cu.sha256_hex(data), language=None)


def read_upload(uploaded) -> bytes:
    return uploaded.getvalue()


def show_valid() -> None:
    st.success("## ✅ VALID\nThe signature matches this document and this public key.")
    st.info(
        "A valid signature proves that (1) the document is byte-for-byte identical to what was "
        "signed and (2) the signature was made with the private key matching the public key you "
        "supplied. It does **not** prove *who* owns that key - you must obtain the public key "
        "from a source you trust."
    )


def show_invalid() -> None:
    st.error("## ❌ INVALID\nThe signature does NOT match this document and public key.")
    st.write(
        "Possible reasons: the document was changed (even by one byte), the signature file was "
        "damaged or belongs to another document, or the public key does not belong to the "
        "signer. Do not trust this document."
    )


def show_cannot_process(err: Exception) -> None:
    st.warning(f"### ⚠️ Cannot be processed\n{err}")
    st.caption(
        "This is **not** a verification result: the input could not be read, so nothing was "
        "verified. Fix the problem above and try again."
    )


def download_sample_files() -> None:
    files = [
        ("sample_document.txt", "text/plain"),
        ("sample_document.txt.sig", "application/octet-stream"),
        ("sample_public_key.pem", "application/x-pem-file"),
        ("sample_document_tampered.txt", "text/plain"),
    ]
    available = [(n, m) for n, m in files if (SAMPLE_DIR / n).is_file()]
    if not available:
        st.caption("Sample files were not found in the sample_files folder.")
        return
    cols = st.columns(len(available))
    for col, (name, mime) in zip(cols, available):
        col.download_button(name, (SAMPLE_DIR / name).read_bytes(), file_name=name, mime=mime, key=f"dl_sample_{name}")


# ------------------------------------------------------------------------ pages
def page_home() -> None:
    st.title("🔏 Digital Signature Verification System")
    st.write(
        "A mini-project that shows how **digital signatures** let you check that a document "
        "has not been altered (**integrity**) and was signed by the holder of a particular "
        "private key (**authenticity of the key holder**). It uses **RSA-PSS with SHA-256**."
    )
    st.subheader("What you can do here")
    st.markdown(
        """
1. **Generate Keys** - create an RSA key pair (2048-bit) and download the PEM files.
2. **Sign a Document** - upload a file and a private key; download a separate signature file.
3. **Verify a Signature** - upload the document, signature and public key to get VALID / INVALID.
4. **Tampering Demonstration** - change one character or one bit and watch verification fail.
5. **About the Cryptographic Algorithms** - RSA, SHA-256, PSS and key concepts explained.
"""
    )
    st.subheader("How it works")
    st.code(
        "SIGNING (sender, has the PRIVATE key)\n"
        "  document --SHA-256--> hash --RSA-PSS sign with private key--> signature (.sig)\n"
        "\n"
        "VERIFYING (anyone, has the PUBLIC key)\n"
        "  document + signature + public key --> RSA-PSS verify (SHA-256) --> VALID / INVALID\n",
        language=None,
    )
    st.subheader("Quick start")
    st.write(
        "Try **Tampering Demonstration** first - it needs no files. For a file-based walkthrough, "
        "download the sample files below and use them on the *Verify a Signature* page."
    )
    with st.expander("Sample files"):
        download_sample_files()
    st.caption("Educational project. Not a replacement for a certified signing solution.")


def page_generate_keys() -> None:
    st.header("Generate Keys")
    st.write(
        "An RSA key pair has two parts: a **private key** used to create signatures and a "
        "**public key** used by others to verify them. Keys are generated locally by the "
        "`cryptography` library with a 2048-bit modulus."
    )
    private_key_warning()

    if st.button("Generate new 2048-bit RSA key pair", type="primary"):
        private_key, public_key = cu.generate_key_pair()
        st.session_state["gen_keys"] = {
            "private_pem": cu.private_key_to_pem(private_key),
            "public_pem": cu.public_key_to_pem(public_key),
            "fingerprint": cu.public_key_fingerprint(public_key),
        }

    keys = st.session_state.get("gen_keys")
    if not keys:
        st.info("No keys generated yet. Click the button above.")
        return

    st.success("Key pair generated.")
    col1, col2 = st.columns(2)
    col1.download_button(
        "⬇ Download private key (private_key.pem)",
        keys["private_pem"],
        file_name="private_key.pem",
        mime="application/x-pem-file",
        key="dl_gen_private",
    )
    col2.download_button(
        "⬇ Download public key (public_key.pem)",
        keys["public_pem"],
        file_name="public_key.pem",
        mime="application/x-pem-file",
        key="dl_gen_public",
    )
    st.caption("The private key is intentionally not displayed on screen. Store it safely and never share it.")
    st.write("**Public key** (safe to share):")
    st.code(keys["public_pem"].decode("ascii"), language=None)
    st.write("**Public key fingerprint** (SHA-256 of the key; lets you check two public keys are identical):")
    st.code(keys["fingerprint"], language=None)
    if st.button("Clear generated keys from this session"):
        st.session_state.pop("gen_keys", None)
        st.rerun()


def page_sign() -> None:
    st.header("Sign a Document")
    st.write(
        "The document is read as raw bytes and signed with **RSA-PSS (MGF1-SHA256, SHA-256, "
        "maximum salt length)**. The original file is never modified; the signature is a "
        "separate file."
    )
    document = st.file_uploader("1. Document to sign (any file type, max 10 MB)", key="sign_doc")

    st.write("**2. Private key**")
    source = st.radio(
        "Key source",
        ["Upload an existing private key (PEM)", "Generate a new key pair now"],
        key="sign_key_source",
        label_visibility="collapsed",
    )
    private_key = None
    key_error = None
    if source.startswith("Upload"):
        key_file = st.file_uploader("Private key (.pem, unencrypted PKCS#8)", key="sign_key_file")
        if key_file is not None:
            try:
                private_key = cu.load_private_key(read_upload(key_file))
                st.caption("Private key loaded (contents are not displayed).")
            except cu.CryptoInputError as err:
                key_error = err
    else:
        if st.button("Generate key pair for signing"):
            priv, pub = cu.generate_key_pair()
            st.session_state["sign_keys"] = {
                "private_pem": cu.private_key_to_pem(priv),
                "public_pem": cu.public_key_to_pem(pub),
            }
        if "sign_keys" in st.session_state:
            private_key = cu.load_private_key(st.session_state["sign_keys"]["private_pem"])
            st.caption("A new key pair is ready. Download the keys below after signing.")
    private_key_warning()

    if key_error is not None:
        show_cannot_process(key_error)

    if st.button("Sign document", type="primary"):
        st.session_state.pop("sign_result", None)
        if document is None:
            st.error("Please upload a document first.")
        elif private_key is None:
            if key_error is None:
                st.error("Please provide a private key (upload one or generate a new pair).")
        else:
            data = read_upload(document)
            try:
                signature = cu.sign_document(data, private_key)
            except cu.CryptoInputError as err:
                show_cannot_process(err)
            else:
                st.session_state["sign_result"] = {
                    "doc_name": document.name,
                    "doc_sha256": cu.sha256_hex(data),
                    "signature": signature,
                    "public_fingerprint": cu.public_key_fingerprint(private_key.public_key()),
                    "public_pem": cu.public_key_to_pem(private_key.public_key()),
                    "generated": not source.startswith("Upload"),
                }

    result = st.session_state.get("sign_result")
    if result:
        st.success(f"Signature created for **{result['doc_name']}** ({len(result['signature'])} bytes).")
        st.download_button(
            "⬇ Download signature",
            result["signature"],
            file_name=f"{result['doc_name']}.sig",
            mime="application/octet-stream",
            key="dl_signature",
        )
        st.caption("Document SHA-256 (what was signed, after hashing):")
        st.code(result["doc_sha256"], language=None)
        st.caption("Public key fingerprint (the key needed to verify this signature):")
        st.code(result["public_fingerprint"], language=None)
        st.download_button(
            "⬇ Download matching public key (public_key.pem)",
            result["public_pem"],
            file_name="public_key.pem",
            mime="application/x-pem-file",
            key="dl_sign_public",
        )
        if result["generated"] and "sign_keys" in st.session_state:
            st.download_button(
                "⬇ Download the generated private key (private_key.pem)",
                st.session_state["sign_keys"]["private_pem"],
                file_name="private_key.pem",
                mime="application/x-pem-file",
                key="dl_sign_private",
            )
            st.caption("Keep this file secret. Without it you cannot sign again with this key.")
        st.info("Send the document, the signature and the **public** key to the verifier. Never the private key.")


def page_verify() -> None:
    st.header("Verify a Signature")
    st.write("Upload the three files below. Verification uses RSA-PSS with SHA-256.")
    document = st.file_uploader("1. Original document", key="ver_doc")
    signature_file = st.file_uploader("2. Signature file (.sig)", key="ver_sig")
    key_file = st.file_uploader("3. Signer's public key (.pem)", key="ver_key")

    if not st.button("Verify signature", type="primary"):
        return

    missing = [n for n, f in [("document", document), ("signature", signature_file), ("public key", key_file)] if f is None]
    if missing:
        st.error("Please upload: " + ", ".join(missing) + ".")
        return

    data = read_upload(document)
    try:
        public_key = cu.load_public_key(read_upload(key_file))
        is_valid = cu.verify_signature(data, read_upload(signature_file), public_key)
    except cu.CryptoInputError as err:
        show_cannot_process(err)
        return

    if is_valid:
        show_valid()
    else:
        show_invalid()
    with st.expander("Technical details"):
        show_hash("SHA-256 of the uploaded document", data)
        st.caption("Public key fingerprint")
        st.code(cu.public_key_fingerprint(public_key), language=None)
        st.caption(f"Signature size: {len(read_upload(signature_file))} bytes")


def _tamper_one_char() -> None:
    text = st.session_state.get("demo_received", "")
    if text:
        # Change the last character: always alters at least one byte of the document.
        st.session_state["demo_received"] = text[:-1] + ("X" if text[-1] != "X" else "Y")
    else:
        st.session_state["demo_received"] = "X"


def _restore_original() -> None:
    st.session_state["demo_received"] = st.session_state["demo_signed_text"]


def page_tamper() -> None:
    st.header("Tampering Demonstration")
    st.write(
        "A signature is bound to the exact bytes that were signed. Changing **even a single "
        "byte** gives a completely different SHA-256 hash, so verification fails."
    )

    st.subheader("Part 1 - Live demo (no files needed)")
    st.write("**Step 1.** Edit the text if you like, then sign it with a temporary demo key.")
    text = st.text_area("Document text", value=DEMO_TEXT, height=150, key="demo_text")
    if st.button("Sign this text with a temporary demo key", type="primary"):
        data = text.encode("utf-8")
        try:
            priv, pub = cu.generate_key_pair()
            signature = cu.sign_document(data, priv)
        except cu.CryptoInputError as err:
            show_cannot_process(err)
        else:
            st.session_state["demo_signed_text"] = text
            st.session_state["demo_received"] = text
            st.session_state["demo_signature"] = signature
            st.session_state["demo_public_pem"] = cu.public_key_to_pem(pub)
            del priv  # the demo private key is discarded immediately

    if "demo_signature" in st.session_state:
        st.write(
            "**Step 2.** This is the copy a recipient receives. Modify it (type in the box, then "
            "press Ctrl+Enter / click outside) or use the buttons, and watch the result."
        )
        col1, col2 = st.columns(2)
        col1.button("Change one character", on_click=_tamper_one_char)
        col2.button("Restore original", on_click=_restore_original)
        received = st.text_area("Received document", height=150, key="demo_received")

        original_bytes = st.session_state["demo_signed_text"].encode("utf-8")
        received_bytes = received.encode("utf-8")
        public_key = cu.load_public_key(st.session_state["demo_public_pem"])
        try:
            ok = cu.verify_signature(received_bytes, st.session_state["demo_signature"], public_key)
        except cu.CryptoInputError as err:
            show_cannot_process(err)
        else:
            if ok:
                show_valid()
            else:
                show_invalid()
        differing = sum(a != b for a, b in zip(original_bytes, received_bytes)) + abs(len(original_bytes) - len(received_bytes))
        st.caption(f"Bytes that differ from the signed original: {differing}")
        show_hash("SHA-256 of the signed original", original_bytes)
        show_hash("SHA-256 of the received document", received_bytes)

    st.divider()
    st.subheader("Part 2 - Create a tampered copy of a real file")
    st.write(
        "Upload any file you have signed. A tampered copy is produced by flipping **one bit** at "
        "the chosen byte position; your original is not changed. Verify the tampered copy on the "
        "*Verify a Signature* page with the original signature and public key - it must be INVALID."
    )
    upload = st.file_uploader("File to tamper with", key="tamper_file")
    if upload is not None:
        data = read_upload(upload)
        try:
            cu.validate_document(data)
        except cu.CryptoInputError as err:
            show_cannot_process(err)
        else:
            index = st.number_input(
                f"Byte position to modify (0 - {len(data) - 1})", min_value=0, max_value=len(data) - 1, value=0, step=1
            )
            tampered = cu.flip_one_bit(data, int(index))
            show_hash("SHA-256 of the original file", data)
            show_hash("SHA-256 of the tampered copy (1 bit different)", tampered)
            st.download_button(
                "⬇ Download tampered copy",
                tampered,
                file_name=f"tampered_{upload.name}",
                mime="application/octet-stream",
                key="dl_tampered",
            )

    with st.expander("Ready-made sample files (document, signature, public key, tampered copy)"):
        download_sample_files()
        st.caption(
            "Verify sample_document.txt with the .sig and public key: VALID. "
            "Verify sample_document_tampered.txt with the same signature: INVALID."
        )


def page_about() -> None:
    st.header("About the Cryptographic Algorithms")

    st.subheader("Digital signature")
    st.write(
        "A digital signature is a value computed from a document and a private key. Anyone with "
        "the matching public key can check that the value was produced for exactly that "
        "document. It provides **integrity** (any change is detected), **authentication of the "
        "key holder** and **non-repudiation** (the key holder cannot easily deny signing, "
        "assuming the private key was kept secret)."
    )

    st.subheader("RSA")
    st.write(
        "RSA is a public-key (asymmetric) algorithm based on the difficulty of factoring the "
        "product of two large primes. A key pair has a **public key** (modulus *n*, exponent "
        "*e*) and a **private key** (exponent *d*). Operations with *d* can be checked with *e*, "
        "but *d* cannot practically be derived from *e* and *n* when *n* is large. This project "
        "uses 2048-bit moduli with *e* = 65537."
    )

    st.subheader("SHA-256")
    st.write(
        "SHA-256 is a cryptographic hash function that maps data of any length to a 256-bit "
        "digest. It is deterministic, fast, and designed so that it is infeasible to find two "
        "inputs with the same digest or to reverse the digest. A one-bit change in the input "
        "changes the digest completely (the *avalanche effect*). Signing the digest instead of "
        "the whole file keeps RSA operations small and fast."
    )

    st.subheader("RSA-PSS padding")
    st.write(
        "Raw RSA is not safe to use directly. **PSS** (Probabilistic Signature Scheme) adds a "
        "random salt and a mask generation function (**MGF1** with SHA-256) before the RSA "
        "operation. This project uses SHA-256, MGF1-SHA256 and the maximum salt length "
        "(`PSS.MAX_LENGTH`). Because of the random salt, signing the same document twice yields "
        "different - but equally valid - signatures."
    )

    st.subheader("Private key and public key")
    st.markdown(
        "- **Private key**: secret; used only to *sign*. If it leaks, others can forge your signatures.\n"
        "- **Public key**: shareable; used to *verify*. It cannot be used to create signatures."
    )

    st.subheader("Signing and verification workflow")
    st.code(
        "SIGN                                       VERIFY\n"
        "----                                       ------\n"
        "document bytes                             document bytes (received)\n"
        "     |                                          |\n"
        "  SHA-256 -> digest                          SHA-256 -> digest\n"
        "     |                                          |\n"
        "  PSS encode (salt + MGF1)                   signature --RSA public op--> decode PSS\n"
        "     |                                          |\n"
        "  RSA private-key operation                  digests match?  YES -> VALID\n"
        "     |                                                       NO  -> INVALID\n"
        "  signature (.sig)",
        language=None,
    )

    st.subheader("Encryption vs. digital signature")
    st.table(
        {
            "": ["Goal", "Key used to protect", "Key used to check/undo", "Who can do it", "Document stays readable?"],
            "Encryption": [
                "Confidentiality (hide content)",
                "Recipient's public key",
                "Recipient's private key",
                "Anyone can encrypt; only the recipient decrypts",
                "No - the content is hidden",
            ],
            "Digital signature": [
                "Integrity and key-holder authentication",
                "Signer's private key",
                "Signer's public key",
                "Only the signer signs; anyone verifies",
                "Yes - the document is not hidden",
            ],
        }
    )

    st.subheader("What a valid signature does and does not prove")
    st.markdown(
        "- ✅ The document is **identical** to the one that was signed.\n"
        "- ✅ The signature was created with the **private key matching the public key** you used.\n"
        "- ❌ It does **not** prove the real-world identity of the signer. Linking a public key to a "
        "person or organisation needs a trust mechanism (for example certificates issued by a "
        "certificate authority, or exchanging the key through a trusted channel). That is outside "
        "the scope of this project.\n"
        "- ❌ It does not say *when* the document was signed or that the content is true."
    )


# ------------------------------------------------------------------------ router
def main() -> None:
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", PAGES, key="page")
    st.sidebar.caption("RSA-PSS · SHA-256 · Python `cryptography`")
    {
        PAGES[0]: page_home,
        PAGES[1]: page_generate_keys,
        PAGES[2]: page_sign,
        PAGES[3]: page_verify,
        PAGES[4]: page_tamper,
        PAGES[5]: page_about,
    }[page]()


main()
