# This file is part of the KeepKey project.
#
# Copyright (C) 2025 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.

import pytest
import unittest

try:
    from keepkeylib import messages_ton_pb2 as _ton_msgs
    _has_ton = hasattr(_ton_msgs, 'TonGetAddress')
except Exception:
    _has_ton = False
import common
import binascii
import struct
import hashlib
import json
import os
import base64

from keepkeylib import messages_pb2 as messages
from keepkeylib import messages_ton_pb2 as ton_messages
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

TON_PATH = "m/44'/607'/0'/0'/0'/0'"


def make_ton_address(workchain=0, hash_bytes=None, bounceable=True):
    """Build a base64url TON address string."""
    if hash_bytes is None:
        hash_bytes = b'\xAA' * 32
    tag = 0x11 if bounceable else 0x51
    raw = bytes([tag, workchain & 0xFF]) + hash_bytes
    crc = binascii.crc_hqx(raw, 0)
    raw += struct.pack('>H', crc)
    return base64.b64encode(raw).decode('ascii')


@unittest.skipUnless(_has_ton, "TON protobuf messages not available in this build")
class TestMsgTonSignTx(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("TonGetAddress")
        self.requires_message("TonGetAddress")

    def _verified_message(self, path=TON_PATH, memo_len=0):
        """A real WalletV4R2 body hash from the independent @ton/core oracle.

        Older firmware blind-signs this same hash under AdvancedMode. Native
        contact firmware verifies the fields before reviewing/signing it.
        """
        with open(os.path.join(os.path.dirname(__file__), 'ton_transfer_vectors.json')) as f:
            vectors = json.load(f)
        v = next(v for v in vectors if v['amount'] == '1000000000'
                 and v['workchain'] == 0 and v['bounce'] and len(v['memo']) == memo_len)
        return ton_messages.TonSignTx(
            address_n=parse_path(path), raw_tx=bytes.fromhex(v['hash']),
            to_address=v['address'], amount=int(v['amount']), seqno=v['seqno'],
            expire_at=v['expiry'], workchain=0, bounce=True, memo=v['memo'])

    def test_ton_get_address(self):
        """Test TON address derivation from device."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()

        msg = ton_messages.TonGetAddress(
            address_n=parse_path(TON_PATH),
            show_display=False,
        )
        resp = self.client.call(msg)

        self.assertTrue(resp.raw_address is not None or resp.address is not None)

    def test_ton_sign_structured(self):
        """Test TON transfer with structured fields + raw_tx hash.

        The firmware requires raw_tx even when structured fields are present.
        Clear-sign mode activates when raw_tx is exactly 32 bytes (a SHA-256
        hash of the unsigned body cell tree).  The firmware reconstructs the
        cell tree from the structured fields and verifies the hash matches.

        Without a Python cell-hash implementation, we send a non-matching
        32-byte raw_tx which causes the firmware to fall back to blind-sign
        with the structured fields shown as display context.
        """
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # 7.14.2 gates TonSignTx behind AdvancedMode: the device cannot parse
        # raw_tx, so every TonSignTx is a blind signature and must be disclosed
        # as one. This test exercises signing correctness, so it opts in
        # explicitly rather than the firmware relaxing the gate.
        self.client.apply_policy("AdvancedMode", 1)

        dest_addr = make_ton_address()

        # 64-byte raw_tx triggers blind-sign path (not 32-byte hash path)
        # Structured fields (to_address, amount) are used for display context
        raw_tx = hashlib.sha256(b'test-ton-structured').digest() * 2  # 64 bytes

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=1000000000,  # 1 TON in nanotons
            seqno=1,
            expire_at=1700000000,
            bounce=True,
        )
        if 32 in self.client.features.capabilities:
            with self.assertRaises(CallException):
                self.client.call(msg)
        else:
            resp = self.client.call(msg)
            self.assertEqual(len(resp.signature), 64)
            self.assertFalse(all(b == 0 for b in resp.signature))

    def test_ton_sign_with_memo(self):
        """Test TON transfer with a text memo (blind-sign path)."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # 7.14.2 gates TonSignTx behind AdvancedMode: the device cannot parse
        # raw_tx, so every TonSignTx is a blind signature and must be disclosed
        # as one. This test exercises signing correctness, so it opts in
        # explicitly rather than the firmware relaxing the gate.
        self.client.apply_policy("AdvancedMode", 1)

        dest_addr = make_ton_address()

        # raw_tx required; 64 bytes = blind-sign path with display context
        raw_tx = hashlib.sha256(b'test-ton-memo').digest() * 2

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
            to_address=dest_addr,
            amount=500000000,  # 0.5 TON
            seqno=2,
            expire_at=1700000000,
            memo="Hello TON!",
        )
        if 32 in self.client.features.capabilities:
            with self.assertRaises(CallException):
                self.client.call(msg)
        else:
            resp = self.client.call(msg)
            self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_legacy_raw_tx(self):
        """Test legacy blind-sign with raw_tx field."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # 7.14.2 gates TonSignTx behind AdvancedMode: the device cannot parse
        # raw_tx, so every TonSignTx is a blind signature and must be disclosed
        # as one. This test exercises signing correctness, so it opts in
        # explicitly rather than the firmware relaxing the gate.
        self.client.apply_policy("AdvancedMode", 1)

        raw_tx = b'\x00' * 64

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
        )
        resp = self.client.call(msg)

        self.assertEqual(len(resp.signature), 64)

    def test_ton_sign_missing_fields_rejected(self):
        """Test that incomplete structured fields are rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # Same 7.14.2 AdvancedMode gate as the signing tests above, but this is
        # a reject-path test: with the gate CLOSED the firmware refuses every
        # TonSignTx, so the assertion below would pass without the parser ever
        # validating anything. Opt in so the rejection proves what it claims.
        self.client.apply_policy("AdvancedMode", 1)

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            to_address=make_ton_address(),
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_deterministic(self):
        """The same verified WalletV4R2 transfer has the same signature."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)  # older blind-only firmware
        msg = self._verified_message()
        self.assertEqual(self.client.call(msg).signature, self.client.call(msg).signature)

    def test_ton_sign_empty_raw_tx(self):
        """Empty raw_tx (0 bytes) should be rejected by firmware."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # Same 7.14.2 AdvancedMode gate as the signing tests above, but this is
        # a reject-path test: with the gate CLOSED the firmware refuses every
        # TonSignTx, so the assertion below would pass without the parser ever
        # validating anything. Opt in so the rejection proves what it claims.
        self.client.apply_policy("AdvancedMode", 1)

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=b'',
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_oversized_raw_tx(self):
        """raw_tx of 1025 bytes exceeds proto max (1024) and should be rejected."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        # Same 7.14.2 AdvancedMode gate as the signing tests above, but this is
        # a reject-path test: with the gate CLOSED the firmware refuses every
        # TonSignTx, so the assertion below would pass without the parser ever
        # validating anything. Opt in so the rejection proves what it claims.
        self.client.apply_policy("AdvancedMode", 1)

        raw_tx = b'\xAB' * 1025

        msg = ton_messages.TonSignTx(
            address_n=parse_path(TON_PATH),
            raw_tx=raw_tx,
        )

        with pytest.raises(CallException):
            self.client.call(msg)

    def test_ton_sign_with_empty_memo(self):
        """An empty comment binds to the independently built empty-body hash."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)
        self.assertEqual(len(self.client.call(self._verified_message(memo_len=0)).signature), 64)

    def test_ton_sign_with_long_memo(self):
        """A 120-byte comment binds to the independently built referenced cell."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)
        self.assertEqual(len(self.client.call(self._verified_message(memo_len=120)).signature), 64)

    def test_ton_sign_workchain_zero(self):
        """An explicit basechain recipient is checked against its body hash."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)
        response = self.client.call(self._verified_message())
        self.assertEqual(len(response.signature), 64)
        self.assertFalse(all(b == 0 for b in response.signature))

    def test_ton_sign_workchain_default(self):
        """Omitting workchain matches the explicit workchain in the address."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)
        msg = self._verified_message()
        explicit = self.client.call(msg)
        msg.ClearField('workchain')
        default = self.client.call(msg)
        self.assertEqual(default.signature, explicit.signature)

    def test_ton_sign_different_accounts(self):
        """The same signed transfer hash under different account keys differs."""
        self.requires_fullFeature()
        self.setup_mnemonic_allallall()
        self.client.apply_policy("AdvancedMode", 1)
        first = self.client.call(self._verified_message("m/44'/607'/0'/0'/0'/0'"))
        second = self.client.call(self._verified_message("m/44'/607'/1'/0'/0'/0'"))
        self.assertEqual(len(first.signature), 64)
        self.assertEqual(len(second.signature), 64)
        self.assertNotEqual(first.signature, second.signature)


if __name__ == '__main__':
    unittest.main()
