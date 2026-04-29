# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

import binascii
import unittest

import pytest

try:
    from keepkeylib import messages_tron_pb2 as _tron_msgs
    _has_tron_signmessage = hasattr(_tron_msgs, 'TronSignMessage')
except Exception:
    _has_tron_signmessage = False

import common
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


TRON_DEFAULT_PATH = "m/44'/195'/0'/0/0"


@unittest.skipUnless(
    _has_tron_signmessage,
    "TronSignMessage protobuf not available in this build",
)
class TestMsgTronSignMessage(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("TronSignMessage")

    def test_sign_text_roundtrip(self):
        """TIP-191 sign of printable text, then verify with the same client."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        message = b"Hello, TRON!"
        sig_resp = self.client.tron_sign_message(
            parse_path(TRON_DEFAULT_PATH),
            message,
        )

        # Signature shape: 65 bytes (r || s || v=27|28)
        self.assertEqual(len(sig_resp.signature), 65)
        self.assertIn(sig_resp.signature[64], (27, 28))

        # Address shape: 34-char Base58Check starting with 'T'
        self.assertEqual(len(sig_resp.address), 34)
        self.assertTrue(sig_resp.address.startswith('T'))

        # Round-trip verify: same address, same signature, same message → Success
        verify_resp = self.client.tron_verify_message(
            address=sig_resp.address,
            signature=sig_resp.signature,
            message=message,
        )
        self.assertEqual(verify_resp.message, "Message verified")

    def test_sign_bytes_roundtrip(self):
        """TIP-191 sign of non-printable bytes; falls into the 'Sign Bytes' UX path."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        message = bytes.fromhex(
            "1df3d10be935abc63b6561cb6148b745eef81f6d2517f420fc0f59684fb3d4cb"
        )
        sig_resp = self.client.tron_sign_message(
            parse_path(TRON_DEFAULT_PATH),
            message,
        )
        self.assertEqual(len(sig_resp.signature), 65)

        verify_resp = self.client.tron_verify_message(
            address=sig_resp.address,
            signature=sig_resp.signature,
            message=message,
        )
        self.assertEqual(verify_resp.message, "Message verified")

    def test_sign_empty_message(self):
        """TIP-191 permits zero-length message (hash includes ASCII '0' length)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        sig_resp = self.client.tron_sign_message(
            parse_path(TRON_DEFAULT_PATH),
            b"",
        )
        self.assertEqual(len(sig_resp.signature), 65)

        verify_resp = self.client.tron_verify_message(
            address=sig_resp.address,
            signature=sig_resp.signature,
            message=b"",
        )
        self.assertEqual(verify_resp.message, "Message verified")

    def test_sign_address_matches_get_address(self):
        """The address returned in the signature must match tron_get_address()."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        addr_resp = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=False,
        )
        sig_resp = self.client.tron_sign_message(
            parse_path(TRON_DEFAULT_PATH),
            b"address-binding-check",
        )
        self.assertEqual(sig_resp.address, addr_resp.address)

    def test_verify_rejects_corrupted_signature(self):
        """A signature with one flipped byte must fail verification."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        message = b"original message"
        sig_resp = self.client.tron_sign_message(
            parse_path(TRON_DEFAULT_PATH),
            message,
        )

        # Flip a byte inside r||s (NOT the recovery id) so recovery still
        # produces some pubkey but not the signer's.
        bad = bytearray(sig_resp.signature)
        bad[10] ^= 0xFF

        with pytest.raises(CallException):
            self.client.tron_verify_message(
                address=sig_resp.address,
                signature=bytes(bad),
                message=message,
            )

    def test_verify_rejects_wrong_message(self):
        """Verifying a valid signature against a different message must fail."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        sig_resp = self.client.tron_sign_message(
            parse_path(TRON_DEFAULT_PATH),
            b"message A",
        )

        with pytest.raises(CallException):
            self.client.tron_verify_message(
                address=sig_resp.address,
                signature=sig_resp.signature,
                message=b"message B",
            )

    def test_invalid_path_rejected(self):
        """Non-TRON BIP-44 paths must be rejected by the firmware path guard."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        # m/44'/60'/0'/0/0 is Ethereum, not TRON
        with pytest.raises(CallException):
            self.client.tron_sign_message(
                parse_path("m/44'/60'/0'/0/0"),
                b"wrong-chain",
            )


if __name__ == "__main__":
    unittest.main()
