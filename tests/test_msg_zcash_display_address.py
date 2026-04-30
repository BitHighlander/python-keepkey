# Zcash unified address display tests.
#
# ZcashDisplayAddress now derives the Orchard-only Unified Address on-device
# (Sinsemilla + SWU hash-to-curve, default diversifier index 0) and shows it
# with a QR code on the OLED. There is no host-supplied address or FVK to
# validate — what appears on screen is bound to the device's seed.

import unittest
import common

from keepkeylib import messages_zcash_pb2 as zcash_proto

# Hardened offset
H = 0x80000000


class TestMsgZcashDisplayAddress(common.KeepKeyTest):
    """Test device-derived Zcash unified address display."""

    def setUp(self):
        super().setUp()
        self.requires_firmware("7.15.0")
        self.requires_message("ZcashDisplayAddress")

    def test_zcash_display_address_basic(self):
        """Device derives and returns its Orchard-only UA."""
        self.setup_mnemonic_allallall()

        resp = self.client.call(
            zcash_proto.ZcashDisplayAddress(
                address_n=[H + 32, H + 133, H + 0],
                account=0,
            )
        )

        self.assertIsInstance(resp, zcash_proto.ZcashAddress)
        self.assertTrue(resp.HasField("address"))
        self.assertTrue(resp.address.startswith("u1"))
        self.assertTrue(resp.HasField("seed_fingerprint"))
        self.assertEqual(len(resp.seed_fingerprint), 32)


if __name__ == '__main__':
    unittest.main()
