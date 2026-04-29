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
    from keepkeylib import messages_tron_pb2 as _tron_msgs
    _has_typed_hash = hasattr(_tron_msgs, 'TronSignTypedHash')
except Exception:
    _has_typed_hash = False

import common
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


TRON_DEFAULT_PATH = "m/44'/195'/0'/0/0"

# 32-byte hashes — host-precomputed per TIP-712 spec.
DOMAIN_HASH = bytes.fromhex(
    "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
)
MESSAGE_HASH = bytes.fromhex(
    "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
)


@unittest.skipUnless(
    _has_typed_hash,
    "TronSignTypedHash protobuf not available in this build",
)
class TestMsgTronSignTypedHash(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("TronSignTypedHash")

    def test_sign_typed_hash_with_message(self):
        """TIP-712 hash mode with both domain and message hashes."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        resp = self.client.tron_sign_typed_hash(
            parse_path(TRON_DEFAULT_PATH),
            domain_separator_hash=DOMAIN_HASH,
            message_hash=MESSAGE_HASH,
        )

        # 65-byte recoverable secp256k1 signature
        self.assertEqual(len(resp.signature), 65)
        self.assertIn(resp.signature[64], (27, 28))

        # Address must be Base58Check ("T...", 34 chars)
        self.assertEqual(len(resp.address), 34)
        self.assertTrue(resp.address.startswith('T'))

    def test_sign_typed_hash_domain_only(self):
        """primaryType='EIP712Domain' case: no message_hash."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        resp = self.client.tron_sign_typed_hash(
            parse_path(TRON_DEFAULT_PATH),
            domain_separator_hash=DOMAIN_HASH,
        )
        self.assertEqual(len(resp.signature), 65)
        self.assertTrue(resp.address.startswith('T'))

    def test_sign_typed_hash_address_matches_get_address(self):
        """Returned address must match tron_get_address() at the same path."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        addr_resp = self.client.tron_get_address(
            parse_path(TRON_DEFAULT_PATH),
            show_display=False,
        )
        sig_resp = self.client.tron_sign_typed_hash(
            parse_path(TRON_DEFAULT_PATH),
            domain_separator_hash=DOMAIN_HASH,
            message_hash=MESSAGE_HASH,
        )
        self.assertEqual(sig_resp.address, addr_resp.address)

    def test_invalid_domain_hash_length_rejected(self):
        """31-byte domain hash must be rejected (must be exactly 32)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.tron_sign_typed_hash(
                parse_path(TRON_DEFAULT_PATH),
                domain_separator_hash=b"\x00" * 31,  # too short
                message_hash=MESSAGE_HASH,
            )

    def test_invalid_message_hash_length_rejected(self):
        """33-byte message hash must be rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.tron_sign_typed_hash(
                parse_path(TRON_DEFAULT_PATH),
                domain_separator_hash=DOMAIN_HASH,
                message_hash=b"\x00" * 33,  # too long
            )

    def test_invalid_path_rejected(self):
        """Non-TRON BIP-44 path must be rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        with pytest.raises(CallException):
            self.client.tron_sign_typed_hash(
                parse_path("m/44'/60'/0'/0/0"),  # Ethereum path
                domain_separator_hash=DOMAIN_HASH,
                message_hash=MESSAGE_HASH,
            )


if __name__ == "__main__":
    unittest.main()
