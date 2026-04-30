# Zcash Orchard PCZT signing protocol tests.
#
# Tests the ZcashSignPCZT / ZcashPCZTAction / ZcashPCZTActionAck flow
# via the zcash_sign_pczt() client helper against the emulator.

import unittest
import common
import os


class TestZcashSignPCZT(common.KeepKeyTest):
    """Test Zcash Orchard PCZT signing protocol."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.14.0")
        self.requires_message("ZcashGetOrchardFVK")

    def _make_action(self, index, sighash=None, value=10000, is_spend=True):
        """Build a minimal action dict for testing."""
        action = {
            'alpha': os.urandom(32),
            'value': value,
            'is_spend': is_spend,
        }
        if sighash is not None:
            action['sighash'] = sighash
        return action

    def test_single_action_legacy_sighash(self):
        """Single-action signing with host-provided sighash (legacy mode)."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xab' * 32

        actions = [self._make_action(0, sighash=sighash)]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=10000,
            fee=1000,
        )

        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)

    def test_multi_action_legacy_sighash(self):
        """Multi-action signing with host-provided sighash."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xcd' * 32

        actions = [
            self._make_action(0, sighash=sighash, value=5000),
            self._make_action(1, sighash=sighash, value=5000),
        ]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=10000,
            fee=1000,
        )

        self.assertEqual(len(resp.signatures), 2)
        for sig in resp.signatures:
            self.assertEqual(len(sig), 64)

    def test_signatures_are_64_bytes(self):
        """Every returned signature must be exactly 64 bytes."""
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xef' * 32

        actions = [self._make_action(i, sighash=sighash) for i in range(3)]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=30000,
            fee=1000,
        )

        self.assertEqual(len(resp.signatures), 3)
        for sig in resp.signatures:
            self.assertEqual(len(sig), 64)
            self.assertTrue(sig != b'\x00' * 64)

    def test_different_accounts_different_signatures(self):
        """Same transaction with different accounts must produce different sigs."""
        self.setup_mnemonic_allallall()

        sighash = b'\x11' * 32
        alpha = b'\x01' * 31 + b'\x00'

        actions_0 = [{'alpha': alpha, 'sighash': sighash,
                      'value': 10000, 'is_spend': True}]
        actions_1 = [{'alpha': alpha, 'sighash': sighash,
                      'value': 10000, 'is_spend': True}]

        resp0 = self.client.zcash_sign_pczt(
            address_n=[0x80000000 + 32, 0x80000000 + 133, 0x80000000],
            actions=actions_0,
            total_amount=10000,
            fee=1000,
        )
        resp1 = self.client.zcash_sign_pczt(
            address_n=[0x80000000 + 32, 0x80000000 + 133, 0x80000001],
            actions=actions_1,
            total_amount=10000,
            fee=1000,
        )

        self.assertTrue(resp0.signatures[0] != resp1.signatures[0],
                        "Different accounts must produce different signatures")

    def test_transparent_shielding_single_input(self):
        """Hybrid shielding: one transparent input + one Orchard action.

        Exercises Phase 3: the host signs the transparent input first,
        then transitions to the Orchard phase. The device returns one
        ECDSA DER signature per transparent input (in ZcashTransparentSig)
        and one 64-byte RedPallas signature per Orchard action.
        """
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xaa' * 32

        actions = [self._make_action(0, sighash=sighash, value=50000)]

        # Transparent input: BIP-44 Zcash path m/44'/133'/0'/0/0
        transparent_inputs = [{
            'address_n': [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 0],
            'amount': 100000,
            'sighash': sighash,
        }]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=50000,
            fee=1000,
            transparent_inputs=transparent_inputs,
        )

        # Final response is ZcashSignedPCZT with Orchard signatures.
        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)

    def test_transparent_shielding_multiple_inputs(self):
        """Two transparent inputs feeding into one Orchard action.

        Verifies that the device drives the transparent loop to its 0xFF
        completion sentinel before accepting any Orchard action.
        """
        self.setup_mnemonic_allallall()

        address_n = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]
        sighash = b'\xbb' * 32

        actions = [self._make_action(0, sighash=sighash, value=100000)]

        transparent_inputs = [
            {
                'address_n': [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 0],
                'amount': 60000,
                'sighash': sighash,
            },
            {
                'address_n': [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 1],
                'amount': 50000,
                'sighash': sighash,
            },
        ]

        resp = self.client.zcash_sign_pczt(
            address_n=address_n,
            actions=actions,
            total_amount=100000,
            fee=10000,
            transparent_inputs=transparent_inputs,
        )

        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)


if __name__ == '__main__':
    unittest.main()
