# Zcash transparent shielding protocol tests.
#
# Tests ZcashTransparentInput / ZcashTransparentSig flow:
# - Happy path with cryptographic signature verification
# - Path validation (7 rejection cases)
# - Phase ordering (transparent must complete before Orchard)
# - Edge cases (too many inputs, bad index ordering)

import unittest
import common
import os
import hashlib

import ecdsa
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_zcash_pb2 as zcash_proto
from keepkeylib import types_pb2 as types

# Check if the proto has transparent shielding messages (requires updated pb2)
_HAS_TRANSPARENT = hasattr(zcash_proto, 'ZcashTransparentInput')

# Zcash BIP44 path: m/44'/133'/0'/0/0
ZEC_PATH = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 0]
# Orchard ZIP-32 path: m/32'/133'/0'
ORCHARD_PATH = [0x80000000 + 32, 0x80000000 + 133, 0x80000000]


@unittest.skipUnless(_HAS_TRANSPARENT,
    "ZcashTransparentInput not in pb2 — regenerate proto bindings from updated device-protocol")
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

    def _make_transparent_input(self, index=0, address_n=None, amount=100000,
                                sighash=None):
        """Build a transparent input dict with valid defaults."""
        return {
            'index': index,
            'sighash': sighash or os.urandom(32),
            'address_n': address_n or ZEC_PATH,
            'amount': amount,
        }

    def _get_pubkey_for_path(self, path):
        """Get the compressed public key for a BIP44 path from the device."""
        resp = self.client.get_public_node(path, coin_name='Zcash')
        return bytes(resp.node.public_key)

    def _verify_der_signature(self, pubkey_bytes, sighash, der_sig):
        """Verify a DER ECDSA signature against a compressed pubkey and digest."""
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
        try:
            vk.verify_digest(der_sig, sighash, sigdecode=sigdecode_der)
            return True
        except ecdsa.BadSignatureError:
            return False

    # ═══════════════════════════════════════════════════════════════
    # 1. Happy path with signature verification
    # ═══════════════════════════════════════════════════════════════

    def test_hybrid_signature_verifies(self):
        """Transparent DER signature must verify against the device's pubkey."""
        self.setup_mnemonic_allallall()

        # Get the public key the device will sign with
        pubkey = self._get_pubkey_for_path(ZEC_PATH)
        self.assertEqual(len(pubkey), 33)  # compressed

        # Use a known sighash so we can verify
        sighash = hashlib.sha256(b'test transparent shielding').digest()
        tinputs = [self._make_transparent_input(sighash=sighash)]
        actions = [self._make_action(0, sighash=b'\xab' * 32)]

        resp, tsigs = self.client.zcash_sign_pczt_hybrid(
            address_n=ORCHARD_PATH,
            actions=actions,
            transparent_inputs=tinputs,
            total_amount=100000,
            fee=10000,
        )

        # Verify Orchard signature shape
        self.assertEqual(len(resp.signatures), 1)
        self.assertEqual(len(resp.signatures[0]), 64)

        # Verify transparent signature cryptographically
        self.assertEqual(len(tsigs), 1)
        self.assertTrue(
            self._verify_der_signature(pubkey, sighash, bytes(tsigs[0])),
            "Transparent DER signature must verify against device pubkey"
        )

    def test_hybrid_multi_input_signatures_verify(self):
        """Multiple transparent inputs: each signature verifies for its sighash."""
        self.setup_mnemonic_allallall()

        pubkey = self._get_pubkey_for_path(ZEC_PATH)

        sighash_0 = hashlib.sha256(b'input 0').digest()
        sighash_1 = hashlib.sha256(b'input 1').digest()

        tinputs = [
            self._make_transparent_input(index=0, amount=60000, sighash=sighash_0),
            self._make_transparent_input(index=1, amount=40000, sighash=sighash_1),
        ]
        actions = [
            self._make_action(0, sighash=b'\xcd' * 32, value=50000),
            self._make_action(1, sighash=b'\xcd' * 32, value=50000),
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

        # Each transparent sig verifies against the correct sighash
        self.assertTrue(
            self._verify_der_signature(pubkey, sighash_0, bytes(tsigs[0])),
            "Transparent sig[0] must verify against sighash_0"
        )
        self.assertTrue(
            self._verify_der_signature(pubkey, sighash_1, bytes(tsigs[1])),
            "Transparent sig[1] must verify against sighash_1"
        )

        # Cross-check: sig[0] must NOT verify against sighash_1
        self.assertFalse(
            self._verify_der_signature(pubkey, sighash_1, bytes(tsigs[0])),
            "Transparent sig[0] must not verify against wrong sighash"
        )

    def test_wrong_key_does_not_verify(self):
        """Signature for account 0 must not verify against account 1's pubkey."""
        self.setup_mnemonic_allallall()

        # Get pubkeys for two different paths
        path_0 = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 0]
        path_1 = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 0, 1]
        pubkey_0 = self._get_pubkey_for_path(path_0)
        pubkey_1 = self._get_pubkey_for_path(path_1)
        self.assertNotEqual(pubkey_0, pubkey_1)

        sighash = hashlib.sha256(b'cross-key test').digest()
        tinputs = [self._make_transparent_input(address_n=path_0, sighash=sighash)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]

        resp, tsigs = self.client.zcash_sign_pczt_hybrid(
            address_n=ORCHARD_PATH,
            actions=actions,
            transparent_inputs=tinputs,
            total_amount=100000,
            fee=10000,
        )

        # Verifies against the signing key
        self.assertTrue(self._verify_der_signature(pubkey_0, sighash, bytes(tsigs[0])))
        # Does NOT verify against a different key
        self.assertFalse(self._verify_der_signature(pubkey_1, sighash, bytes(tsigs[0])))

    # ═══════════════════════════════════════════════════════════════
    # 2. Path validation
    # ═══════════════════════════════════════════════════════════════

    def test_rejects_wrong_purpose(self):
        """Path with wrong purpose (49') must be rejected."""
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
        """Path with ETH coin type (60') must be rejected."""
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
        """Account without hardened bit must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0, 0, 0]
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]
        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("hardened", str(ctx.exception).lower())

    def test_rejects_wrong_account(self):
        """Account 1 rejected when session approved account 0."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000001, 0, 0]
        tinputs = [self._make_transparent_input(address_n=bad_path)]
        actions = [self._make_action(0, sighash=b'\x00' * 32)]
        with self.assertRaises(Exception) as ctx:
            self.client.zcash_sign_pczt_hybrid(
                address_n=ORCHARD_PATH, actions=actions,
                transparent_inputs=tinputs, total_amount=100000, fee=10000)
        self.assertIn("account", str(ctx.exception).lower())

    def test_rejects_short_path(self):
        """Only 3 path components must be rejected."""
        self.setup_mnemonic_allallall()
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000000]
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
        bad_path = [0x80000000 + 44, 0x80000000 + 133, 0x80000000, 7, 0]
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
    # 3. Phase ordering
    # ═══════════════════════════════════════════════════════════════

    def test_orchard_before_transparent_rejected(self):
        """Sending ZcashPCZTAction before completing transparent inputs must fail."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(zcash_proto.ZcashSignPCZT(
            address_n=ORCHARD_PATH,
            n_actions=1,
            n_transparent_inputs=1,
            total_amount=100000,
            fee=10000,
        ))
        self.assertIsInstance(resp, zcash_proto.ZcashPCZTActionAck)

        # Skip transparent input, send Orchard action directly
        resp = self.client.call(zcash_proto.ZcashPCZTAction(
            index=0, alpha=os.urandom(32), sighash=b'\xee' * 32,
            value=100000, is_spend=True,
        ))
        self.assertIsInstance(resp, proto.Failure)
        self.assertIn("transparent", resp.message.lower())

    # ═══════════════════════════════════════════════════════════════
    # 4. Edge cases
    # ═══════════════════════════════════════════════════════════════

    def test_rejects_out_of_order_transparent_index(self):
        """Transparent input with wrong index must be rejected."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(zcash_proto.ZcashSignPCZT(
            address_n=ORCHARD_PATH,
            n_actions=1,
            n_transparent_inputs=2,
            total_amount=100000,
            fee=10000,
        ))
        self.assertIsInstance(resp, zcash_proto.ZcashPCZTActionAck)

        # Send index 1 first (should expect index 0)
        resp = self.client.call(zcash_proto.ZcashTransparentInput(
            index=1,
            sighash=os.urandom(32),
            address_n=ZEC_PATH,
            amount=50000,
        ))
        self.assertIsInstance(resp, proto.Failure)
        self.assertIn("index", resp.message.lower())

    def test_rejects_too_many_transparent_inputs(self):
        """n_transparent_inputs exceeding ZCASH_MAX_TRANSPARENT_INPUTS must be rejected."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(zcash_proto.ZcashSignPCZT(
            address_n=ORCHARD_PATH,
            n_actions=1,
            n_transparent_inputs=100,  # way over limit (8)
            total_amount=100000,
            fee=10000,
        ))
        # Should fail at the ZcashSignPCZT stage
        self.assertIsInstance(resp, proto.Failure)
        self.assertIn("transparent", resp.message.lower())


if __name__ == '__main__':
    unittest.main()
