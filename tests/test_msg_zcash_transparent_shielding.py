# Zcash transparent shielding protocol tests.
#
# Tests ZcashTransparentInput / ZcashTransparentSig flow and the
# security constraints: path validation, account enforcement, and
# transparent-phase ordering.

import unittest
import common
import os

from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_zcash_pb2 as zcash_proto


# Zcash BIP44 path: m/44'/133'/0'/0/0
ZEC_PATH = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 0]
# Orchard ZIP-32 path: m/32'/133'/0'
ORCHARD_PATH = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]


class TestZcashTransparentShielding(common.KeepKeyTest):
    """Test transparent-to-Orchard hybrid signing protocol."""

    def _make_action(self, index, sighash=None, value=10000, is_spend=True):
        """Build a minimal Orchard action dict."""
        action = {
            'alpha': os.urandom(32),
            'value': value,
            'is_spend': is_spend,
        }
        if sighash is not None:
            action['sighash'] = sighash
        return action

    def _make_transparent_input(self, index=0, address_n=None, amount=100000):
        """Build a transparent input dict with valid defaults."""
        return {
            'index': index,
            'sighash': os.urandom(32),
            'address_n': address_n or ZEC_PATH,
            'amount': amount,
        }

    # ═══════════════════════════════════════════════════════════════
    # 1. Happy path: hybrid shielding works end-to-end
    # ═══════════════════════════════════════════════════════════════

    def test_hybrid_single_input_single_action(self):
        """Hybrid tx with 1 transparent input + 1 Orchard action succeeds."""
        self.setup_mnemonic_allallall()
        sighash = b'\xab' * 32
        actions = [self._make_action(0, sighash=sighash)]
        tinputs = [self._make_transparent_input()]

        resp, tsigs = self.client.zcash_sign_pczt_hybrid(
            address_n=ORCHARD_PATH,
            actions=actions,
            transparent_inputs=tinputs,
            total_amount=100000,
            fee=10000,
        )

        # Orchard signatures
        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)

        # Transparent DER signature
        self.assertEqual(len(tsigs), 1)
        self.assertTrue(len(tsigs[0]) >= 68)  # DER min ~70 bytes
        self.assertTrue(len(tsigs[0]) <= 73)

    def test_hybrid_multi_input(self):
        """Hybrid tx with 2 transparent inputs + 2 Orchard actions."""
        self.setup_mnemonic_allallall()
        sighash = b'\xcd' * 32
        actions = [
            self._make_action(0, sighash=sighash, value=50000),
            self._make_action(1, sighash=sighash, value=50000),
        ]
        tinputs = [
            self._make_transparent_input(index=0, amount=60000),
            self._make_transparent_input(index=1, amount=40000),
        ]

        resp, tsigs = self.client.zcash_sign_pczt_hybrid(
            address_n=ORCHARD_PATH,
            actions=actions,
            transparent_inputs=tinputs,
            total_amount=100000,
            fee=10000,
        )

        self.assertEqual(len(resp.signatures), 2)
        self.assertEqual(len(tsigs), 2)

    # ═══════════════════════════════════════════════════════════════
    # 2. Path validation: exact m/44'/133'/account'/change/index
    # ═══════════════════════════════════════════════════════════════

    def test_rejects_wrong_purpose(self):
        """Path with wrong purpose (49' instead of 44') must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 49, 0x80000000 + 133, 0x80000000, 0, 0]
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("44'/133'", str(ctx.exception))

    def test_rejects_wrong_coin_type(self):
        """Path with wrong coin type (60' ETH instead of 133' ZEC) must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 60, 0x80000000, 0, 0]
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("44'/133'", str(ctx.exception))

    def test_rejects_unhardened_account(self):
        """Path with unhardened account must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0, 0, 0]  # account NOT hardened
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("hardened", str(ctx.exception).lower())

    def test_rejects_wrong_account(self):
        """Transparent input with account 1 must be rejected when session approved account 0."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000001, 0, 0]  # account 1
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH,  # account 0
                actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("account", str(ctx.exception).lower())

    def test_rejects_short_path(self):
        """Path with fewer than 5 components must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000000]  # only 3 components
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("44'/133'/account'/change/index", str(ctx.exception))

    def test_rejects_bad_change(self):
        """Change value > 1 must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 7, 0]  # change=7
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("0 or 1", str(ctx.exception))

    def test_rejects_hardened_index(self):
        """Hardened address index must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 0x80000000]
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("hardened", str(ctx.exception).lower())

    # ═══════════════════════════════════════════════════════════════
    # 3. Phase ordering: transparent must complete before Orchard
    # ═══════════════════════════════════════════════════════════════

    def test_orchard_before_transparent_rejected(self):
        """Sending ZcashPCZTAction before completing transparent inputs must fail.

        We use low-level call() to bypass the client helper's sequencing
        and test the firmware's state machine directly."""
        self.setup_mnemonic_allallall()
        sighash = b'\xee' * 32

        # Start a hybrid session with 1 transparent input
        resp = self.client.call(zcash_proto.ZcashSignPCZT(
            address_n=ORCHARD_PATH,
            n_actions=1,
            n_transparent_inputs=1,
            total_amount=100000,
            fee=10000,
        ))
        self.assertIsInstance(resp, zcash_proto.ZcashPCZTActionAck)

        # Skip the transparent input and send an Orchard action directly
        resp = self.client.call(zcash_proto.ZcashPCZTAction(
            index=0,
            alpha=os.urandom(32),
            sighash=sighash,
            value=100000,
            is_spend=True,
        ))

        # Device must reject — transparent phase not complete
        self.assertIsInstance(resp, proto.Failure)
        self.assertIn("transparent", resp.message.lower())


if __name__ == '__main__':
    unittest.main()
