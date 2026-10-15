"""Automated tests for crypto_utils.py (run with: python -m pytest -v)."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

import crypto_utils as cu

DOC = b"This is the original document.\nPay 100 to Alice.\n"


@pytest.fixture(scope="module")
def keys():
    return cu.generate_key_pair()


@pytest.fixture(scope="module")
def other_keys():
    return cu.generate_key_pair()


@pytest.fixture(scope="module")
def signature(keys):
    return cu.sign_document(DOC, keys[0])


# ---------------------------------------------------------------- key generation
def test_generate_key_pair_is_rsa_2048(keys):
    private_key, public_key = keys
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert isinstance(public_key, rsa.RSAPublicKey)
    assert private_key.key_size >= 2048
    assert public_key.public_numbers() == private_key.public_key().public_numbers()


def test_generated_pairs_are_unique(keys, other_keys):
    assert cu.public_key_to_pem(keys[1]) != cu.public_key_to_pem(other_keys[1])


@pytest.mark.parametrize("size", [512, 1024, 2047])
def test_weak_key_size_is_refused(size):
    with pytest.raises(ValueError):
        cu.generate_key_pair(size)


def test_pem_round_trip(keys):
    private_key, public_key = keys
    priv_pem = cu.private_key_to_pem(private_key)
    pub_pem = cu.public_key_to_pem(public_key)
    assert priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert cu.load_private_key(priv_pem).private_numbers() == private_key.private_numbers()
    assert cu.load_public_key(pub_pem).public_numbers() == public_key.public_numbers()


def test_fingerprint_is_stable_and_distinct(keys, other_keys):
    fp = cu.public_key_fingerprint(keys[1])
    assert fp == cu.public_key_fingerprint(cu.load_public_key(cu.public_key_to_pem(keys[1])))
    assert len(fp) == 64
    assert fp != cu.public_key_fingerprint(other_keys[1])


# ------------------------------------------------------------- sign and verify
def test_sign_and_verify_succeeds(keys, signature):
    assert cu.verify_signature(DOC, signature, keys[1]) is True


def test_signature_length_matches_key_size(keys, signature):
    assert len(signature) == keys[0].key_size // 8


def test_signing_is_randomised_but_both_signatures_verify(keys):
    sig1 = cu.sign_document(DOC, keys[0])
    sig2 = cu.sign_document(DOC, keys[0])
    assert sig1 != sig2  # PSS uses a random salt
    assert cu.verify_signature(DOC, sig1, keys[1])
    assert cu.verify_signature(DOC, sig2, keys[1])


def test_signing_does_not_modify_document(keys):
    data = bytearray(DOC)
    cu.sign_document(data, keys[0])
    assert bytes(data) == DOC


def test_signature_matches_independent_pss_verification(keys, signature):
    """Cross-check with raw cryptography calls using the documented parameters."""
    keys[1].verify(
        signature,
        DOC,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def test_binary_document_round_trip(keys):
    data = bytes(range(256)) * 50
    sig = cu.sign_document(data, keys[0])
    assert cu.verify_signature(data, sig, keys[1])


# ------------------------------------------------------------ failure scenarios
def test_modified_document_fails(keys, signature):
    assert cu.verify_signature(DOC + b" ", signature, keys[1]) is False
    assert cu.verify_signature(DOC.replace(b"100", b"900"), signature, keys[1]) is False


def test_single_bit_flip_in_any_position_fails(keys, signature):
    for index in (0, len(DOC) // 2, len(DOC) - 1):
        tampered = cu.flip_one_bit(DOC, index)
        assert tampered != DOC
        assert len(tampered) == len(DOC)
        assert cu.verify_signature(tampered, signature, keys[1]) is False


def test_flip_one_bit_leaves_original_untouched():
    original = bytes(DOC)
    cu.flip_one_bit(original, 3)
    assert original == DOC


def test_flip_one_bit_rejects_bad_index():
    with pytest.raises(IndexError):
        cu.flip_one_bit(DOC, len(DOC))
    with pytest.raises(IndexError):
        cu.flip_one_bit(DOC, -1)


def test_wrong_public_key_fails(other_keys, signature):
    assert cu.verify_signature(DOC, signature, other_keys[1]) is False


def test_corrupted_signature_fails(keys, signature):
    corrupted = bytearray(signature)
    corrupted[10] ^= 0xFF
    assert cu.verify_signature(DOC, bytes(corrupted), keys[1]) is False


def test_truncated_and_extended_signature_fail(keys, signature):
    assert cu.verify_signature(DOC, signature[:-1], keys[1]) is False
    assert cu.verify_signature(DOC, signature + b"\x00", keys[1]) is False


def test_random_garbage_signature_fails(keys):
    assert cu.verify_signature(DOC, b"A" * 256, keys[1]) is False
    assert cu.verify_signature(DOC, b"not a signature", keys[1]) is False


def test_signature_for_another_document_fails(keys):
    sig_other = cu.sign_document(b"a completely different document", keys[0])
    assert cu.verify_signature(DOC, sig_other, keys[1]) is False


# ---------------------------------------------------------- malformed key input
@pytest.mark.parametrize(
    "bad",
    [b"", b"   \n", b"hello world", b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", b"\x00\x01\x02"],
)
def test_malformed_private_key_rejected(bad):
    with pytest.raises(cu.KeyLoadError):
        cu.load_private_key(bad)


@pytest.mark.parametrize(
    "bad",
    [b"", b"  ", b"hello world", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", b"\xff\xfe"],
)
def test_malformed_public_key_rejected(bad):
    with pytest.raises(cu.KeyLoadError):
        cu.load_public_key(bad)


def test_public_key_given_as_private_key_rejected(keys):
    with pytest.raises(cu.KeyLoadError):
        cu.load_private_key(cu.public_key_to_pem(keys[1]))


def test_private_key_given_as_public_key_rejected_with_clear_message(keys):
    with pytest.raises(cu.KeyLoadError, match="PRIVATE"):
        cu.load_public_key(cu.private_key_to_pem(keys[0]))


def test_encrypted_private_key_rejected_with_clear_message(keys):
    encrypted = keys[0].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    )
    with pytest.raises(cu.KeyLoadError, match="password"):
        cu.load_private_key(encrypted)


def test_non_rsa_keys_rejected():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = ec_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub_pem = ec_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(cu.KeyLoadError):
        cu.load_private_key(priv_pem)
    with pytest.raises(cu.KeyLoadError):
        cu.load_public_key(pub_pem)


def test_weak_rsa_keys_rejected_on_load():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    priv_pem = weak.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub_pem = weak.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(cu.KeyLoadError, match="2048"):
        cu.load_private_key(priv_pem)
    with pytest.raises(cu.KeyLoadError, match="2048"):
        cu.load_public_key(pub_pem)


def test_key_error_messages_do_not_leak_key_material(keys):
    pem = cu.private_key_to_pem(keys[0])
    body_line = pem.splitlines()[2].decode()
    with pytest.raises(cu.KeyLoadError) as exc:
        cu.load_public_key(pem)
    assert body_line not in str(exc.value)


# ---------------------------------------------------- empty / invalid documents
def test_empty_document_cannot_be_signed(keys):
    with pytest.raises(cu.DocumentError, match="empty"):
        cu.sign_document(b"", keys[0])


def test_empty_document_cannot_be_verified(keys, signature):
    with pytest.raises(cu.DocumentError):
        cu.verify_signature(b"", signature, keys[1])


def test_oversized_document_rejected(keys, monkeypatch):
    monkeypatch.setattr(cu, "MAX_FILE_SIZE", 10)
    with pytest.raises(cu.DocumentError, match="limit"):
        cu.sign_document(b"x" * 11, keys[0])


def test_non_bytes_document_rejected(keys):
    with pytest.raises(cu.DocumentError):
        cu.sign_document("a string, not bytes", keys[0])


def test_empty_signature_is_a_processing_error_not_invalid(keys):
    with pytest.raises(cu.SignatureFormatError):
        cu.verify_signature(DOC, b"", keys[1])


def test_oversized_signature_file_is_a_processing_error(keys):
    with pytest.raises(cu.SignatureFormatError):
        cu.verify_signature(DOC, b"\x00" * 5000, keys[1])


def test_all_input_errors_share_a_base_class():
    for exc in (cu.KeyLoadError, cu.DocumentError, cu.SignatureFormatError):
        assert issubclass(exc, cu.CryptoInputError)


# --------------------------------------------------------------- file handling
def test_file_based_workflow(tmp_path, keys):
    doc = tmp_path / "contract.txt"
    doc.write_bytes(DOC)
    (tmp_path / "private.pem").write_bytes(cu.private_key_to_pem(keys[0]))
    (tmp_path / "public.pem").write_bytes(cu.public_key_to_pem(keys[1]))

    private_key = cu.load_private_key((tmp_path / "private.pem").read_bytes())
    sig = cu.sign_document(doc.read_bytes(), private_key)
    (tmp_path / "contract.txt.sig").write_bytes(sig)
    assert doc.read_bytes() == DOC  # original unchanged

    public_key = cu.load_public_key((tmp_path / "public.pem").read_bytes())
    assert cu.verify_signature(doc.read_bytes(), (tmp_path / "contract.txt.sig").read_bytes(), public_key)

    doc.write_bytes(cu.flip_one_bit(doc.read_bytes(), 0))
    assert not cu.verify_signature(doc.read_bytes(), (tmp_path / "contract.txt.sig").read_bytes(), public_key)


def test_filename_is_irrelevant_only_bytes_matter(tmp_path, keys, signature):
    (tmp_path / "a.txt").write_bytes(DOC)
    (tmp_path / "renamed.bin").write_bytes(DOC)
    for name in ("a.txt", "renamed.bin"):
        assert cu.verify_signature((tmp_path / name).read_bytes(), signature, keys[1])


def test_sha256_hex_known_vector():
    assert cu.sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sample_files_behave_as_documented():
    """The shipped sample files: genuine verifies, tampered copy does not."""
    sample_dir = Path(__file__).resolve().parent.parent / "sample_files"
    pub = cu.load_public_key((sample_dir / "sample_public_key.pem").read_bytes())
    sig = (sample_dir / "sample_document.txt.sig").read_bytes()
    assert cu.verify_signature((sample_dir / "sample_document.txt").read_bytes(), sig, pub)
    assert not cu.verify_signature((sample_dir / "sample_document_tampered.txt").read_bytes(), sig, pub)
    assert not list(sample_dir.glob("*private*")), "no private key may ship with the project"
