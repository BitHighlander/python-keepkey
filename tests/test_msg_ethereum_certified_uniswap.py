# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Uniswap on Base: the certified approve to Permit2, with AdvancedMode off.

APPROVE_ENVELOPE is the exact signedPayload the deployed ClearSign Worker
returned on 2026-10-03 (source revision 77121a317) for the Base USDC approve to
Permit2, certified by the Base (8453) certificate from the 2026-10-03 root
ceremony. The swap tests went with the on-device Universal Router decoder
(removed 2026-10-04, DECISIONS.md D-008/D-009).
"""

import unittest

import common
from keepkeylib.tools import parse_path
from oled_text import TITLE_FONT, find_line, shows
from test_msg_display_disclosure import ScreenRecorder

APPROVE_ENVELOPE = bytes.fromhex(
    "030101000021056b359b004b6565704b657920416c7068612037313600000000"
    "00000000000000000000000342f5f9704494b3f9bd72295eecaf29d783d23ea0"
    "2b2dc9f48abcd2e46d4850cfd3f4638bcd78bd822b88d56dc66bb34c167e3509"
    "597a8d3e86a37f14c5b89a504b04f2868e5fcb3ff93f317e2cae7b1cfca14955"
    "9a272a3ea713125d37757a980500002105833589fcd6edb6e08f4c7c32d4f71b"
    "54bda02913095ea7b30007617070726f766502075370656e6465720600000000"
    "0022d473030f116ddee9f6b43ac78ba30009416c6c6f77616e63650506045553"
    "4443060007556e6973776170454c65742074686520556e697377617020617070"
    "726f76616c20636f6e7472616374207370656e6420757020746f207b317d2066"
    "6f722074726164657320796f75207369676e01000000008087528a4f35ce9aff"
    "ca9aa2423523d70c508f88c69be9027d42fd9379a6fcb33e2cce6c7f2eb0d5bd"
    "46465ab67eb03ee46006804b9d42fccd530ea35c86078d9d1c")





USDC = bytes.fromhex("833589fcd6edb6e08f4c7c32d4f71b54bda02913")
PERMIT2 = bytes.fromhex("000000000022d473030f116ddee9f6b43ac78ba3")
CLASSIFICATION_VERIFIED = 1
KEYID_DELEGATE = 0x80


class TestEthereumCertifiedUniswap(common.KeepKeyTest):
    def setUp(self):
        super(TestEthereumCertifiedUniswap, self).setUp()
        self.requires_firmware("7.16.0")
        self.requires_message("EthereumTxMetadata")
        self.setup_mnemonic_allallall()

    def _sign(self, to, data, envelope):
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=envelope, metadata_version=3, key_id=KEYID_DELEGATE)
        self.assertEqual(resp.classification, CLASSIFICATION_VERIFIED)
        recorder = ScreenRecorder(self.client, answer=True,
                                  screenshot_group="eth-certified-uniswap")
        with recorder:
            sig = self.client.ethereum_sign_tx(
                n=parse_path("m/44'/60'/0'/0/0"), nonce=0,
                gas_price=10**7, gas_limit=200000, to=to, value=0, data=data,
                chain_id=8453)
        self.assertEqual(len(sig[1]), 32)
        return recorder.screens

    def assertScreens(self, screens, expected):
        """Every screen, in order: title and full body. Nothing raw, nothing extra."""
        if len(screens) != len(expected):
            self.fail("%d screens, expected %d" % (len(screens), len(expected)))
        for i, (screen, (title, body)) in enumerate(zip(screens, expected)):
            if find_line(screen, title, TITLE_FONT) is None:
                self.fail("screen %d title is not %r" % (i, title))
            if body is not None and not shows(screen, body):
                self.fail("screen %d (%s) does not show %r" % (i, title, body))

    def test_unlimited_approve_to_permit2_names_uniswap_and_the_limit(self):
        data = (bytes.fromhex("095ea7b3") + b"\0" * 12 + PERMIT2 + b"\xff" * 32)
        screens = self._sign(USDC, data, APPROVE_ENVELOPE)
        self.assertScreens(screens, [
            ("UNISWAP", "Let the Uniswap approval contract spend up to UNLIMITED "
                        "USDC for trades you sign"),
            ("LIMITS", "Can spend up to\nUNLIMITED USDC"),
            ("CONTRACT", None),
            ("SPENDER", None),
            ("KEEPKEY CLEARSIGN", "Described by KeepKey Alpha 716 A9531B9D\n"
                                  "certified by KeepKey"),
            ("TRANSACTION", None),
        ])


if __name__ == "__main__":
    unittest.main()
