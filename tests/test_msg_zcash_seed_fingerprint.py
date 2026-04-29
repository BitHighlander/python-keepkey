# Zcash seed_fingerprint binding tests (ZIP-32 §6.1).
#
# Covers:
#   - calculate_seed_fingerprint() matches the Keystone3 reference vector
#     (cross-checked against keystone3-firmware
#     rust/keystore/src/algorithms/zcash/mod.rs::test_keystore_derive_zcash_ufvk).
#   - ZcashGetOrchardFVK returns the seed_fingerprint.
#   - The fingerprint is consistent across messages on the same device/seed
#     (FVK response, ZcashAddress response).
#   - expected_seed_fingerprint passes when matching, fails when wrong.
#   - Backward compat: omitting expected_seed_fingerprint still works.

import unittest
import pytest

import common

from keepkeylib import messages_zcash_pb2 as zcash_proto
from keepkeylib.client import CallException
from keepkeylib.zcash import calculate_seed_fingerprint

# Hardened offset
H = 0x80000000


class TestMsgZcashSeedFingerprint(common.KeepKeyTest):

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("ZcashGetOrchardFVK")

    # ── Pure helper: no device ────────────────────────────────────────

    def test_helper_reference_vector(self):
        """calculate_seed_fingerprint matches the keystone3-firmware vector.

        seed = 000102...1f, fingerprint =
        deff604c246710f7176dead02aa746f2fd8d5389f7072556dcb555fdbe5e3ae3
        """
        seed = bytes(range(32))
        fp = calculate_seed_fingerprint(seed)
        self.assertEqual(
            fp.hex(),
            "deff604c246710f7176dead02aa746f2fd8d5389f7072556dcb555fdbe5e3ae3",
        )

    def test_helper_rejects_trivial_seeds(self):
        with pytest.raises(ValueError):
            calculate_seed_fingerprint(b"\x00" * 32)
        with pytest.raises(ValueError):
            calculate_seed_fingerprint(b"\xff" * 32)

    def test_helper_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            calculate_seed_fingerprint(b"\x01" * 31)  # too short
        with pytest.raises(ValueError):
            calculate_seed_fingerprint(b"\x01" * 253)  # too long

    # ── Device-backed tests ───────────────────────────────────────────

    def test_get_orchard_fvk_returns_seed_fingerprint(self):
        """ZcashGetOrchardFVK response now includes a 32-byte seed_fingerprint."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0],
            account=0,
        )
        self.assertTrue(fvk.HasField("seed_fingerprint"))
        self.assertEqual(len(fvk.seed_fingerprint), 32)
        # Not all zero (defensive: would mean BLAKE2b returned junk)
        self.assertNotEqual(fvk.seed_fingerprint, b"\x00" * 32)

    def test_fingerprint_stable_across_accounts(self):
        """Fingerprint is bound to the seed, not the account."""
        self.setup_mnemonic_allallall()

        fvk0 = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)
        fvk1 = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 1], account=1)
        self.assertEqual(fvk0.seed_fingerprint, fvk1.seed_fingerprint)

    # ── ZcashDisplayAddress: expected_seed_fingerprint binding ────────

    def test_display_address_accepts_matching_fingerprint(self):
        """DisplayAddress with the device's own fingerprint succeeds."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        resp = self.client.call(
            zcash_proto.ZcashDisplayAddress(
                address_n=[H + 32, H + 133, H + 0],
                account=0,
                address="u1placeholder",
                ak=fvk.ak,
                nk=fvk.nk,
                rivk=fvk.rivk,
                expected_seed_fingerprint=fvk.seed_fingerprint,
            )
        )
        self.assertIsInstance(resp, zcash_proto.ZcashAddress)
        # Response also returns the device's seed_fingerprint
        self.assertTrue(resp.HasField("seed_fingerprint"))
        self.assertEqual(resp.seed_fingerprint, fvk.seed_fingerprint)

    def test_display_address_rejects_wrong_fingerprint(self):
        """DisplayAddress with a wrong fingerprint is rejected before display."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        # Flip one byte to fabricate a non-matching fingerprint
        bad = bytearray(fvk.seed_fingerprint)
        bad[0] ^= 0xFF

        with pytest.raises(CallException):
            self.client.call(
                zcash_proto.ZcashDisplayAddress(
                    address_n=[H + 32, H + 133, H + 0],
                    account=0,
                    address="u1placeholder",
                    ak=fvk.ak,
                    nk=fvk.nk,
                    rivk=fvk.rivk,
                    expected_seed_fingerprint=bytes(bad),
                )
            )

    def test_display_address_backward_compat_no_fingerprint(self):
        """Omitting expected_seed_fingerprint still works (existing flow)."""
        self.setup_mnemonic_allallall()

        fvk = self.client.zcash_get_orchard_fvk(
            address_n=[H + 32, H + 133, H + 0], account=0)

        resp = self.client.call(
            zcash_proto.ZcashDisplayAddress(
                address_n=[H + 32, H + 133, H + 0],
                account=0,
                address="u1placeholder",
                ak=fvk.ak,
                nk=fvk.nk,
                rivk=fvk.rivk,
            )
        )
        self.assertIsInstance(resp, zcash_proto.ZcashAddress)
        # Device still populates seed_fingerprint on responses regardless
        self.assertTrue(resp.HasField("seed_fingerprint"))
        self.assertEqual(resp.seed_fingerprint, fvk.seed_fingerprint)

    # ── ZcashSignPCZT: expected_seed_fingerprint binding ──────────────

    def test_sign_pczt_rejects_wrong_fingerprint(self):
        """SignPCZT with wrong fingerprint is rejected before any signing."""
        self.setup_mnemonic_allallall()

        # Fabricate a fingerprint that's clearly not this seed's.
        wrong_fp = b"\x01" * 32

        # Minimal action — won't actually sign because we expect rejection
        # at the seed-fingerprint check before any key derivation.
        with pytest.raises(CallException):
            self.client.call(
                zcash_proto.ZcashSignPCZT(
                    address_n=[H + 32, H + 133, H + 0],
                    account=0,
                    n_actions=1,
                    total_amount=100000,
                    fee=10000,
                    branch_id=0x37519621,
                    expected_seed_fingerprint=wrong_fp,
                )
            )


if __name__ == '__main__':
    unittest.main()
