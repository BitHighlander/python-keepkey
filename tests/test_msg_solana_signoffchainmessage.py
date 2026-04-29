# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

import struct
import unittest

import pytest

try:
    from keepkeylib import messages_solana_pb2 as _sol_msgs
    _has_offchain = hasattr(_sol_msgs, 'SolanaSignOffchainMessage')
except Exception:
    _has_offchain = False

import common
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


SOLANA_DEFAULT_PATH = "m/44'/501'/0'/0'"

# Per the Solana off-chain message spec:
#   "\xff" || "solana offchain" || version:u8 || format:u8
#         || length:u16 LE      || message bytes
SOL_OFFCHAIN_PREFIX = b"\xffsolana offchain"


def _envelope(message, version=0, message_format=0):
    return (
        SOL_OFFCHAIN_PREFIX
        + bytes([version, message_format])
        + struct.pack("<H", len(message))
        + message
    )


@unittest.skipUnless(
    _has_offchain,
    "SolanaSignOffchainMessage protobuf not available in this build",
)
class TestMsgSolanaSignOffchainMessage(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("SolanaSignOffchainMessage")

    def test_sign_ascii_message(self):
        """Format 0 (ASCII): printable text signs successfully."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        resp = self.client.solana_sign_offchain_message(
            parse_path(SOLANA_DEFAULT_PATH),
            b"Sign this off-chain message",
            message_format=0,
        )
        self.assertEqual(len(resp.signature), 64)   # Ed25519
        self.assertEqual(len(resp.public_key), 32)  # Ed25519

    def test_sign_at_size_ceiling(self):
        """1212-byte message at the spec ceiling for formats 0/1 succeeds."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        resp = self.client.solana_sign_offchain_message(
            parse_path(SOLANA_DEFAULT_PATH),
            b"a" * 1212,
            message_format=0,
        )
        self.assertEqual(len(resp.signature), 64)

    def test_format_2_rejected(self):
        """Extended UTF-8 (format=2) is Ledger-only and not supported on device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.solana_sign_offchain_message(
                parse_path(SOLANA_DEFAULT_PATH),
                b"hello",
                message_format=2,
            )

    def test_invalid_version_rejected(self):
        """Spec defines only version 0; non-zero must be rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.solana_sign_offchain_message(
                parse_path(SOLANA_DEFAULT_PATH),
                b"hello",
                version=1,
            )

    def test_empty_message_rejected(self):
        """Zero-length message rejected with SyntaxError."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.solana_sign_offchain_message(
                parse_path(SOLANA_DEFAULT_PATH),
                b"",
            )

    def test_pubkey_matches_get_address(self):
        """Returned public_key must match SolanaGetAddress at the same path."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        addr_resp = self.client.solana_get_address(
            parse_path(SOLANA_DEFAULT_PATH),
        )
        sig_resp = self.client.solana_sign_offchain_message(
            parse_path(SOLANA_DEFAULT_PATH),
            b"binding-check",
        )
        # Solana addresses are Base58(pubkey); compare by re-encoding the pubkey.
        from keepkeylib import tools
        derived_addr = tools.b58encode(bytes(sig_resp.public_key))
        self.assertEqual(derived_addr, addr_resp.address)

    def test_envelope_signature_verifies_offdevice(self):
        """Signature must verify against the spec envelope, not the bare message.

        This is the load-bearing assertion: if firmware accidentally signs
        msg.message instead of envelope(msg.message), this test catches it.
        """
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        message = b"verify-envelope"
        resp = self.client.solana_sign_offchain_message(
            parse_path(SOLANA_DEFAULT_PATH),
            message,
        )

        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
        except ImportError:
            self.skipTest("nacl not installed; envelope verification skipped")

        envelope = _envelope(message, version=0, message_format=0)
        vk = VerifyKey(bytes(resp.public_key))
        # Should verify the envelope, not the raw message.
        vk.verify(envelope, bytes(resp.signature))

        with self.assertRaises(BadSignatureError):
            vk.verify(message, bytes(resp.signature))


if __name__ == "__main__":
    unittest.main()
