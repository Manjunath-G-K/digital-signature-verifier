"""Smoke tests: every Streamlit page renders without exceptions and the
live tampering demo gives VALID for the original and INVALID after a change."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")

PAGES = [
    "Home / Project Overview",
    "Generate Keys",
    "Sign a Document",
    "Verify a Signature",
    "Tampering Demonstration",
    "About the Cryptographic Algorithms",
]


def make_app(page: str) -> AppTest:
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.session_state["page"] = page
    return at.run()


def all_text(at: AppTest) -> str:
    parts = [e.value for e in at.markdown] + [e.value for e in at.success] + [e.value for e in at.error]
    parts += [e.value for e in at.warning] + [e.value for e in at.info] + [e.value for e in at.caption]
    return "\n".join(parts)


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(page):
    at = make_app(page)
    assert not at.exception


def test_generate_keys_page_hides_private_key():
    at = make_app("Generate Keys")
    at.button[0].click().run()
    assert not at.exception
    shown = "\n".join(c.value for c in at.code)
    assert "BEGIN PUBLIC KEY" in shown
    assert "PRIVATE KEY" not in shown and "PRIVATE KEY" not in all_text(at)


def test_verify_page_requires_all_files():
    at = make_app("Verify a Signature")
    at.button[0].click().run()
    assert not at.exception
    assert any("Please upload" in e.value for e in at.error)
    assert not at.success  # never VALID without inputs


def test_sign_page_requires_document():
    at = make_app("Sign a Document")
    next(b for b in at.button if b.label == "Sign document").click().run()
    assert not at.exception
    assert any("upload a document" in e.value for e in at.error)
    assert not at.success


def test_tamper_demo_valid_then_invalid():
    at = make_app("Tampering Demonstration")
    sign_btn = next(b for b in at.button if b.label.startswith("Sign this text"))
    sign_btn.click().run()
    assert not at.exception
    assert any("VALID" in e.value and "INVALID" not in e.value for e in at.success)
    assert not at.error

    next(b for b in at.button if b.label == "Change one character").click().run()
    assert not at.exception
    assert any("INVALID" in e.value for e in at.error)
    assert not at.success

    next(b for b in at.button if b.label == "Restore original").click().run()
    assert any("VALID" in e.value and "INVALID" not in e.value for e in at.success)
