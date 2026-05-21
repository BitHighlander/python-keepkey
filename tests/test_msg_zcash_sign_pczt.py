# Zcash Orchard PCZT signing protocol tests.
#
# Tests the ZcashSignPCZT / ZcashPCZTAction / ZcashPCZTActionAck flow
# via the zcash_sign_pczt() client helper against the emulator.

import unittest
import common
import hashlib
import os
import struct


class TestZcashSignPCZT(common.KeepKeyTest):
    """Test Zcash Orchard PCZT signing protocol."""

    ORCHARD_FLAGS = 1
    ORCHARD_VALUE_BALANCE = 0
    ORCHARD_ANCHOR = b'\x03' * 32
    TX_VERSION = 5
    VERSION_GROUP_ID = 0x26a7270a
    BRANCH_ID = 0x37519621
    LOCK_TIME = 0
    EXPIRY_HEIGHT = 0
    P2PKH_SCRIPT_11 = (
        b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac'
    )
    P2SH_SCRIPT_22 = (
        b'\xa9\x14' + b'\x22' * 20 + b'\x87'
    )
    P2PKH_SCRIPT_33 = (
        b'\x76\xa9\x14' + b'\x33' * 20 + b'\x88\xac'
    )
    NOTE_COMMIT_RECIPIENT = bytes([
        0x3c, 0x15, 0x0e, 0x60, 0x98, 0xb8, 0x61, 0x71,
        0x6c, 0xc7, 0xf6, 0x28, 0x35, 0xf6, 0x9f, 0xeb,
        0x30, 0x21, 0x93, 0xc9, 0x26, 0x60, 0x44, 0x4f,
        0x26, 0x62, 0x4f, 0xd1, 0x3e, 0x00, 0xea, 0x7a,
        0xc7, 0x74, 0xcd, 0x55, 0x07, 0x4d, 0x63, 0x67,
        0xef, 0xef, 0x37,
    ])
    NOTE_COMMIT_VALUE = 12345678
    NOTE_COMMIT_RHO = bytes([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ])
    NOTE_COMMIT_RSEED = bytes([
        0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ])
    NOTE_COMMIT_CMX = bytes([
        0x02, 0xde, 0xfb, 0x39, 0xc8, 0xf2, 0xe1, 0xec,
        0xc9, 0x45, 0x18, 0x93, 0x73, 0xcf, 0x2a, 0x8e,
        0x21, 0xd4, 0xe1, 0x54, 0x39, 0x8e, 0xfa, 0x16,
        0x21, 0xd5, 0xfb, 0x98, 0x9e, 0x1d, 0xeb, 0x36,
    ])

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("ZcashGetOrchardFVK")

    def _make_action(self, index, sighash=None, value=10000, is_spend=True,
                     digest_fields=True, alpha=None):
        """Build a minimal action dict for testing."""
        action = {
            'alpha': alpha if alpha is not None else os.urandom(32),
            'value': self.NOTE_COMMIT_VALUE,
            'is_spend': is_spend,
        }
        if sighash is not None:
            action['sighash'] = sighash
        if digest_fields:
            action.update({
                'cv_net': bytes([0x10 + index]) * 32,
                'nullifier': self.NOTE_COMMIT_RHO,
                'cmx': self.NOTE_COMMIT_CMX,
                'epk': bytes([0x40 + index]) * 32,
                'enc_compact': bytes([0x50 + index]) * 52,
                'enc_memo': bytes([0x60 + index]) * 512,
                'enc_noncompact': bytes([0x70 + index]) * 564,
                'rk': bytes([0x80 + index]) * 32,
                'out_ciphertext': bytes([0x90 + index]) * 80,
                'recipient': self.NOTE_COMMIT_RECIPIENT,
                'rseed': self.NOTE_COMMIT_RSEED,
            })
        return action

    def _hash_personal(self, personal, *chunks):
        h = hashlib.blake2b(digest_size=32, person=personal)
        for chunk in chunks:
            h.update(chunk)
        return h.digest()

    def _compact_size(self, value):
        if value < 253:
            return struct.pack('<B', value)
        if value <= 0xffff:
            return b'\xfd' + struct.pack('<H', value)
        if value <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', value)
        return b'\xff' + struct.pack('<Q', value)

    def _transparent_digest(self, inputs=None, outputs=None):
        inputs = inputs or []
        outputs = outputs or []
        if not inputs and not outputs:
            return self._hash_personal(b'ZTxIdTranspaHash')

        prevouts = hashlib.blake2b(digest_size=32,
                                   person=b'ZTxIdPrevoutHash')
        sequences = hashlib.blake2b(digest_size=32,
                                    person=b'ZTxIdSequencHash')
        outs_hash = hashlib.blake2b(digest_size=32,
                                    person=b'ZTxIdOutputsHash')

        for txin in inputs:
            prevouts.update(txin['prevout_txid'])
            prevouts.update(struct.pack('<I', txin['prevout_index']))
            sequences.update(struct.pack('<I', txin['sequence']))

        for txout in outputs:
            script = txout['script_pubkey']
            outs_hash.update(struct.pack('<Q', txout['amount']))
            outs_hash.update(self._compact_size(len(script)))
            outs_hash.update(script)

        return self._hash_personal(
            b'ZTxIdTranspaHash',
            prevouts.digest(),
            sequences.digest(),
            outs_hash.digest(),
        )

    def _header_digest(self, tx_version=TX_VERSION,
                       version_group_id=VERSION_GROUP_ID,
                       branch_id=BRANCH_ID, lock_time=LOCK_TIME,
                       expiry_height=EXPIRY_HEIGHT):
        header = struct.pack(
            '<IIIII',
            tx_version | 0x80000000,
            version_group_id,
            branch_id,
            lock_time,
            expiry_height,
        )
        return self._hash_personal(b'ZTxIdHeadersHash', header)

    def _orchard_digest(self, actions, flags=ORCHARD_FLAGS,
                        value_balance=ORCHARD_VALUE_BALANCE,
                        anchor=ORCHARD_ANCHOR):
        compact = hashlib.blake2b(digest_size=32,
                                  person=b'ZTxIdOrcActCHash')
        memos = hashlib.blake2b(digest_size=32,
                                person=b'ZTxIdOrcActMHash')
        noncompact = hashlib.blake2b(digest_size=32,
                                     person=b'ZTxIdOrcActNHash')

        for action in actions:
            compact.update(action['nullifier'])
            compact.update(action['cmx'])
            compact.update(action['epk'])
            compact.update(action['enc_compact'])
            memos.update(action['enc_memo'])
            noncompact.update(action['cv_net'])
            noncompact.update(action['rk'])
            noncompact.update(action['enc_noncompact'])
            noncompact.update(action['out_ciphertext'])

        return self._hash_personal(
            b'ZTxIdOrchardHash',
            compact.digest(),
            memos.digest(),
            noncompact.digest(),
            bytes([flags]),
            struct.pack('<q', value_balance),
            anchor,
        )

    def _verified_request(self, actions, transparent_digest=None, fee=1000,
                          transparent_inputs=None, transparent_outputs=None):
        transparent_inputs = transparent_inputs or []
        transparent_outputs = transparent_outputs or []
        transparent_in = sum(txin['amount'] for txin in transparent_inputs)
        transparent_out = sum(txout['amount'] for txout in transparent_outputs)
        orchard_value_balance = fee - (transparent_in - transparent_out)
        kwargs = {
            'header_digest': self._header_digest(),
            'tx_version': self.TX_VERSION,
            'version_group_id': self.VERSION_GROUP_ID,
            'lock_time': self.LOCK_TIME,
            'expiry_height': self.EXPIRY_HEIGHT,
            'orchard_digest': self._orchard_digest(
                actions, value_balance=orchard_value_balance),
            'orchard_flags': self.ORCHARD_FLAGS,
            'orchard_value_balance': orchard_value_balance,
            'orchard_anchor': self.ORCHARD_ANCHOR,
        }
        if transparent_digest is not None:
            kwargs['transparent_digest'] = transparent_digest
        return kwargs

    def _transparent_input(self, index, amount, script_pubkey=None):
        return {
            'address_n': [
                0x80000000 + 44,
                0x80000000 + 133,
                0x80000000,
                0,
                index,
            ],
            'amount': amount,
            'prevout_txid': bytes([index + 1]) * 32,
            'prevout_index': index,
            'sequence': 0xfffffffe - index,
            'script_pubkey': script_pubkey or self.P2PKH_SCRIPT_11,
        }

    def _transparent_output(self, amount, script_pubkey=None):
        return {
            'amount': amount,
            'script_pubkey': script_pubkey or self.P2PKH_SCRIPT_33,
        }

    def test_rejects_legacy_host_sighash(self):
        """Host-provided per-action sighash must not be accepted."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xab' * 32

        actions = [self._make_action(0, sighash=sighash, digest_fields=False)]

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=actions,
                total_amount=10000,
                fee=1000,
            )

        self.assertIn("Missing transaction digests", str(exc.exception))

    def test_multi_action_device_sighash(self):
        """Multi-action signing uses the device-computed sighash."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]

        actions = [
            self._make_action(0, value=5000),
            self._make_action(1, value=5000),
        ]

        resp, t_signed = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=10000,
            fee=1000,
            **self._verified_request(actions)
        )

        self.assertEqual(len(resp.signatures), 2)
        for sig in resp.signatures:
            self.assertEqual(len(sig), 64)

    def test_rejects_header_digest_mismatch(self):
        """Header digest must match the plaintext header fields."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        actions = [self._make_action(0)]
        request = self._verified_request(actions)
        request['header_digest'] = b'\xff' * 32

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=actions,
                total_amount=10000,
                fee=1000,
                **request
            )

        self.assertIn("Header digest mismatch", str(exc.exception))

    def test_rejects_sapling_digest(self):
        """Sapling is out of scope for this firmware signing path."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        actions = [self._make_action(0)]
        request = self._verified_request(actions)
        request['sapling_digest'] = b'\x00' * 32

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=actions,
                total_amount=10000,
                fee=1000,
                **request
            )

        self.assertIn("Sapling not supported", str(exc.exception))

    def test_rejects_missing_action_digest_fields(self):
        """Every signed action must include fields covered by Orchard digest."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        complete_actions = [self._make_action(0)]
        incomplete_actions = [self._make_action(0, digest_fields=False)]

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=incomplete_actions,
                total_amount=10000,
                fee=1000,
                **self._verified_request(complete_actions)
            )

        self.assertIn("Missing Orchard action data", str(exc.exception))

    def test_rejects_orchard_recipient_mismatch(self):
        """Displayed Orchard recipient must be bound to action cmx."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        complete_actions = [self._make_action(0)]
        tampered_actions = [self._make_action(0)]
        tampered = bytearray(tampered_actions[0]['recipient'])
        tampered[0] ^= 0x01
        tampered_actions[0]['recipient'] = bytes(tampered)

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=tampered_actions,
                total_amount=10000,
                fee=1000,
                **self._verified_request(complete_actions)
            )

        self.assertIn("Orchard note commitment mismatch", str(exc.exception))

    def test_rejects_orchard_value_mismatch(self):
        """Displayed Orchard amount must be bound to action cmx."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        complete_actions = [self._make_action(0)]
        tampered_actions = [self._make_action(0)]
        tampered_actions[0]['value'] = self.NOTE_COMMIT_VALUE + 1

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=tampered_actions,
                total_amount=10000,
                fee=1000,
                **self._verified_request(complete_actions)
            )

        self.assertIn("Orchard note commitment mismatch", str(exc.exception))

    def test_signatures_are_64_bytes(self):
        """Every returned signature must be exactly 64 bytes."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]

        actions = [self._make_action(i) for i in range(3)]

        resp, t_signed = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=30000,
            fee=1000,
            **self._verified_request(actions)
        )

        self.assertEqual(len(resp.signatures), 3)
        for sig in resp.signatures:
            self.assertEqual(len(sig), 64)
            self.assertTrue(sig != b'\x00' * 64)

    def test_different_accounts_different_signatures(self):
        """Same transaction with different accounts must produce different sigs."""
        self.setup_mnemonic_allallall()

        alpha = b'\x01' * 31 + b'\x00'

        actions_0 = [self._make_action(0, alpha=alpha, value=10000)]
        actions_1 = [self._make_action(0, alpha=alpha, value=10000)]

        resp0, _ = self.client.zcash_sign_pczt(
            address_n=[0x80000000 + 32, 0x80000000 + 133, 0x80000000],
            actions=actions_0,
            total_amount=10000,
            fee=1000,
            **self._verified_request(actions_0)
        )
        resp1, _ = self.client.zcash_sign_pczt(
            address_n=[0x80000000 + 32, 0x80000000 + 133, 0x80000001],
            actions=actions_1,
            total_amount=10000,
            fee=1000,
            **self._verified_request(actions_1)
        )

        self.assertTrue(resp0.signatures[0] != resp1.signatures[0],
                        "Different accounts must produce different signatures")

    def test_transparent_shielding_single_input(self):
        """Hybrid shielding: one transparent input + one Orchard action.

        Exercises Phase 3: the host streams transparent plaintext first,
        then transitions to the Orchard phase. The device verifies the
        transparent digest, returns one ECDSA DER signature per transparent
        input in ZcashTransparentSigned, and returns one 64-byte RedPallas
        signature per Orchard action.
        """
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        actions = [self._make_action(0, value=50000)]

        # Transparent input: BIP-44 Zcash path m/44'/133'/0'/0/0
        transparent_inputs = [self._transparent_input(0, 100000)]
        transparent_outputs = [self._transparent_output(49000)]
        transparent_digest = self._transparent_digest(
            transparent_inputs, transparent_outputs)

        resp, t_signed = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=50000,
            fee=1000,
            transparent_inputs=transparent_inputs,
            transparent_outputs=transparent_outputs,
            **self._verified_request(
                actions, transparent_digest, fee=1000,
                transparent_inputs=transparent_inputs,
                transparent_outputs=transparent_outputs)
        )

        # Orchard signatures in ZcashSignedPCZT
        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)
        # Deferred transparent ECDSA sig released at the same gate
        self.assertIsNotNone(t_signed)
        self.assertEqual(len(t_signed.signatures), 1)
        self.assertGreater(len(t_signed.signatures[0]), 0)

    def test_transparent_shielding_multiple_inputs(self):
        """Two transparent inputs feeding into one Orchard action.

        Verifies that transparent ECDSA sigs are released at the final
        approval gate together with ZcashSignedPCZT.
        """
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        actions = [self._make_action(0, value=100000)]

        transparent_inputs = [
            self._transparent_input(0, 60000),
            self._transparent_input(1, 50000, self.P2SH_SCRIPT_22),
        ]
        transparent_digest = self._transparent_digest(transparent_inputs)

        resp, t_signed = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=100000,
            fee=10000,
            transparent_inputs=transparent_inputs,
            **self._verified_request(
                actions, transparent_digest, fee=10000,
                transparent_inputs=transparent_inputs)
        )

        # Orchard signatures in ZcashSignedPCZT
        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)
        # Deferred transparent ECDSA sigs for both inputs
        self.assertIsNotNone(t_signed)
        self.assertEqual(len(t_signed.signatures), 2)

    def test_rejects_host_provided_transparent_sighash(self):
        """Transparent input sighash must be derived on device."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        actions = [self._make_action(0, value=100000)]
        transparent_inputs = [self._transparent_input(0, 100000)]
        transparent_inputs[0]['sighash'] = b'\xaa' * 32
        transparent_digest = self._transparent_digest(transparent_inputs)

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=actions,
                total_amount=100000,
                fee=10000,
                transparent_inputs=transparent_inputs,
                **self._verified_request(
                    actions, transparent_digest, fee=10000,
                    transparent_inputs=transparent_inputs)
            )

        self.assertIn("Host transparent sighash rejected", str(exc.exception))

    def test_rejects_transparent_digest_mismatch(self):
        """Streamed transparent plaintext must match transparent_digest."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        actions = [self._make_action(0, value=100000)]
        transparent_inputs = [self._transparent_input(0, 100000)]

        with self.assertRaises(Exception) as exc:
            self.client.zcash_sign_pczt(
                address_n=address_n,
                actions=actions,
                total_amount=100000,
                fee=10000,
                transparent_inputs=transparent_inputs,
                **self._verified_request(
                    actions, b'\xff' * 32, fee=10000,
                    transparent_inputs=transparent_inputs)
            )

        self.assertIn("Transparent digest mismatch", str(exc.exception))


if __name__ == '__main__':
    unittest.main()
