"""Cryptographic helpers for the Digital Signature Verification System.

All cryptography is delegated to the `cryptography` library:

* RSA key generation (public exponent 65537, 2048-bit minimum)
* RSA-PSS signatures with MGF1-SHA256, SHA-256 and ``PSS.MAX_LENGTH`` salt

Nothing in this module touches the UI, the file system or the network, so it
can be unit-tested on its own.

Error model
-----------
* An *invalid signature* is a normal outcome: ``verify_signature`` returns
  ``False``.
* An input that cannot be processed at all (empty document, malformed key,
  empty signature file, ...) raises a subclass of ``CryptoInputError`` with a
  message that is safe to show to the user. These are never reported as
  "invalid signature", and never as "valid".
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MIN_KEY_SIZE = 2048
DEFAULT_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB upload limit (demo-friendly)


class CryptoInputError(ValueError):
    """Base class for inputs that cannot be processed (not 'invalid signature')."""


class KeyLoadError(CryptoInputError):
    """A PEM key could not be parsed or is not acceptable."""


class DocumentError(CryptoInputError):
    """The document is empty or too large."""


class SignatureFormatError(CryptoInputError):
    """The signature file is empty or too large to be an RSA signature."""


# --------------------------------------------------------------------------
# Padding / hash configuration (single source of truth for sign AND verify)
# --------------------------------------------------------------------------
def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


# --------------------------------------------------------------------------
# Key generation, serialisation and loading
# --------------------------------------------------------------------------
def generate_key_pair(key_size: int = DEFAULT_KEY_SIZE) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a fresh RSA key pair. Key sizes below 2048 bits are refused."""
    if key_size < MIN_KEY_SIZE:
        raise ValueError(f"RSA key size must be at least {MIN_KEY_SIZE} bits.")
    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialise a private key as unencrypted PKCS#8 PEM. Keep the result secret."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialise a public key as SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _check_key_size(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> None:
    if key.key_size < MIN_KEY_SIZE:
        raise KeyLoadError(
            f"The key is only {key.key_size} bits. This project requires RSA keys of at least "
            f"{MIN_KEY_SIZE} bits."
        )


def load_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    """Parse an unencrypted RSA private key in PEM format."""
    if not pem_data or not pem_data.strip():
        raise KeyLoadError("The private key file is empty.")
    try:
        key = serialization.load_pem_private_key(pem_data, password=None)
    except TypeError:
        raise KeyLoadError(
            "This private key is password-protected. Password-protected keys are not supported "
            "by this demo; upload an unencrypted PEM key."
        ) from None
    except (ValueError, UnsupportedAlgorithm):
        raise KeyLoadError(
            "This file is not a valid PEM-encoded private key. Make sure you uploaded the "
            "private key (not the public key) and that the file is not corrupted."
        ) from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyLoadError("The private key is not an RSA key. Only RSA keys are supported.")
    _check_key_size(key)
    return key


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """Parse an RSA public key in PEM format."""
    if not pem_data or not pem_data.strip():
        raise KeyLoadError("The public key file is empty.")
    try:
        key = serialization.load_pem_public_key(pem_data)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        if b"PRIVATE KEY" in pem_data:
            raise KeyLoadError(
                "This file looks like a PRIVATE key. Verification needs the public key. "
                "Never share your private key."
            ) from None
        raise KeyLoadError(
            "This file is not a valid PEM-encoded public key. It may be malformed or corrupted."
        ) from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyLoadError("The public key is not an RSA key. Only RSA keys are supported.")
    _check_key_size(key)
    return key


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 fingerprint (hex) of the DER SubjectPublicKeyInfo encoding.

    Useful for checking visually that two public keys are the same key.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
def validate_document(data: bytes) -> None:
    """Reject empty or oversized documents."""
    if not isinstance(data, (bytes, bytearray)):
        raise DocumentError("The document must be provided as raw bytes.")
    if len(data) == 0:
        raise DocumentError("The document is empty. Please choose a file with some content.")
    if len(data) > MAX_FILE_SIZE:
        raise DocumentError(
            f"The document is larger than the {MAX_FILE_SIZE // (1024 * 1024)} MB limit of this demo."
        )


def _validate_signature_bytes(signature: bytes) -> None:
    if not isinstance(signature, (bytes, bytearray)) or len(signature) == 0:
        raise SignatureFormatError("The signature file is empty.")
    if len(signature) > 4096:  # an RSA-16384 signature is 2048 bytes; anything larger is not one
        raise SignatureFormatError(
            "This file is too large to be an RSA signature. Did you upload the wrong file?"
        )


# --------------------------------------------------------------------------
# Hashing, signing and verification
# --------------------------------------------------------------------------
def sha256_hex(data: bytes) -> str:
    """SHA-256 digest of the bytes as lowercase hex (for display only)."""
    return hashlib.sha256(data).hexdigest()


def sign_document(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign the raw document bytes with RSA-PSS (MGF1-SHA256, SHA-256, max salt)."""
    validate_document(data)
    return private_key.sign(bytes(data), _pss_padding(), hashes.SHA256())


def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Return True only if ``signature`` is a valid RSA-PSS signature over ``data``.

    Returns False for any signature that does not verify (modified document,
    wrong key, corrupted signature, wrong length). Raises ``CryptoInputError``
    for inputs that cannot be processed at all.
    """
    validate_document(data)
    _validate_signature_bytes(signature)
    try:
        public_key.verify(bytes(signature), bytes(data), _pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


# --------------------------------------------------------------------------
# Tampering helper for the demonstration
# --------------------------------------------------------------------------
def flip_one_bit(data: bytes, byte_index: int = 0) -> bytes:
    """Return a copy of ``data`` with a single bit flipped (the original is untouched)."""
    validate_document(data)
    if not 0 <= byte_index < len(data):
        raise IndexError("byte_index is outside the document.")
    modified = bytearray(data)
    modified[byte_index] ^= 0x01
    return bytes(modified)
