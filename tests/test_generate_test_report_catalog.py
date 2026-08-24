"""Tests for build-variant requirements in the release evidence catalog."""

import importlib.util
from pathlib import Path


REPORT_PATH = Path(__file__).parents[1] / "scripts" / "generate-test-report.py"
SPEC = importlib.util.spec_from_file_location("generate_test_report", REPORT_PATH)
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def test_solana_lut_attestation_is_required_on_full_firmware():
    assert REPORT._skip_is_required(
        "test_msg_solana_lut_attestation", "7.15.0", "full"
    )


def test_solana_lut_attestation_is_not_required_on_bitcoin_only():
    assert not REPORT._skip_is_required(
        "test_msg_solana_lut_attestation", "7.15.0", "bitcoin-only"
    )


def test_taproot_is_required_on_both_variants():
    for variant in ("full", "bitcoin-only"):
        assert REPORT._skip_is_required("test_msg_signtx_taproot", "7.15.0", variant)


def test_requirements_do_not_apply_before_their_release():
    assert not REPORT._skip_is_required(
        "test_msg_solana_lut_attestation", "7.14.9", "full"
    )
