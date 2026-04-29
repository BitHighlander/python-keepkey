# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

import unittest

import pytest

try:
    from keepkeylib import messages_ton_pb2 as _ton_msgs
    _has_ton_signmessage = hasattr(_ton_msgs, 'TonSignMessage')
except Exception:
    _has_ton_signmessage = False

import common
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


TON_DEFAULT_PATH = "m/44'/607'/0'"


@unittest.skipUnless(
    _has_ton_signmessage,
    "TonSignMessage protobuf not available in this build",
)
class TestMsgTonSignMessage(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("TonSignMessage")

    def _enable_advanced_mode(self):
        self.client.apply_policy("AdvancedMode", True)

    def _disable_advanced_mode(self):
        self.client.apply_policy("AdvancedMode", False)

    def test_blocked_when_advanced_mode_disabled(self):
        """Without AdvancedMode the handler refuses with ActionCancelled."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self._disable_advanced_mode()

        with pytest.raises(CallException):
            self.client.ton_sign_message(
                parse_path(TON_DEFAULT_PATH),
                b"hello TON",
            )

    def test_sign_text_advanced_mode(self):
        """With AdvancedMode enabled, sign returns 64-byte sig + 32-byte pubkey."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self._enable_advanced_mode()

        try:
            resp = self.client.ton_sign_message(
                parse_path(TON_DEFAULT_PATH),
                b"hello TON",
            )
            self.assertEqual(len(resp.signature), 64)  # Ed25519 signature
            self.assertEqual(len(resp.public_key), 32)  # Ed25519 public key
        finally:
            self._disable_advanced_mode()

    def test_sign_bytes_advanced_mode(self):
        """Non-printable bytes render as hex preview, signing succeeds."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self._enable_advanced_mode()

        try:
            resp = self.client.ton_sign_message(
                parse_path(TON_DEFAULT_PATH),
                bytes.fromhex("deadbeefcafebabe" * 4),
            )
            self.assertEqual(len(resp.signature), 64)
        finally:
            self._disable_advanced_mode()

    def test_empty_message_rejected(self):
        """Zero-length message rejected with SyntaxError (matches Solana SignMessage)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self._enable_advanced_mode()

        try:
            with pytest.raises(CallException):
                self.client.ton_sign_message(
                    parse_path(TON_DEFAULT_PATH),
                    b"",
                )
        finally:
            self._disable_advanced_mode()

    def test_invalid_path_rejected(self):
        """Non-TON BIP-44 path rejected before AdvancedMode gate fires."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.ton_sign_message(
                parse_path("m/44'/501'/0'/0'"),  # Solana path
                b"wrong-chain",
            )

    def test_pubkey_consistency(self):
        """Returned pubkey is stable across calls at the same path."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self._enable_advanced_mode()

        try:
            r1 = self.client.ton_sign_message(parse_path(TON_DEFAULT_PATH), b"msg-A")
            r2 = self.client.ton_sign_message(parse_path(TON_DEFAULT_PATH), b"msg-B")
            self.assertEqual(r1.public_key, r2.public_key)
            # Different messages -> different signatures
            self.assertNotEqual(r1.signature, r2.signature)
        finally:
            self._disable_advanced_mode()


if __name__ == "__main__":
    unittest.main()
