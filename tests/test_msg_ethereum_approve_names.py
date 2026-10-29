# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""7.17: a KeepKey-certified 0x06 name record names the spender of a native
ERC-20 approve, beside its full address. It never changes what is signed.

ETH_UR_NAME and BSC_UR_NAME are production name records from batch 2 of the
2026-10-16 ClearSign ceremony (signed-catalog-batch2.json), certified by the
production root that 7.17 compiles in: Uniswap's Universal Router on
Ethereum, and a router address named on BNB Chain only. COW_APPROVE is the
calldata swaps.pro sent through Desktop on 2026-10-29: approve 25000 USDC to
CoW's GPv2VaultRelayer.
"""

import unittest

import common
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path
from oled_text import TITLE_FONT, find_line, shows
from test_msg_display_disclosure import ScreenRecorder

ETH_UR_NAME = bytes.fromhex(
    "030101000000016cb3ad994b6565704b657920436c6561725369676e00000000"
    "000000000000000000000003bb5314410309cc4e56b8140565106714e4dbf33f"
    "6d75e2c89b78e0e6cb1cd1655c9f942208d3b4812e1a9434993f65d9c05990cb"
    "e379faade132d14987cbfaeb387f0dd3e015210934fe1103770b89272e64a653"
    "97d5d22a3501aa089ea13000060000000166a9893cc07d91d95644aedd05d03f"
    "95e1dba8af18556e697377617020556e6976657273616c20526f757465720100"
    "00000080362cd9a3aa09724ff3758120fc36f96c207a28f4290d7f7415976b75"
    "d090f87d758ad594ec569c63736cc94f4bd63af4d66edd778f6472cd8e8f28e8"
    "860c52be01")
BSC_UR_NAME = bytes.fromhex(
    "030101000000386cb3ad994b6565704b657920436c6561725369676e00000000"
    "00000000000000000000000250edcaf4c63b0922bd1d3171a1bf3ee3fb2dec5d"
    "c8c316c8a0706a079f5ab8021950a0c858d54f27668aff057711a484582d3c56"
    "30fe7246d452ba85fd57a053554d4d22ca57aa97443541bb2dd1b70ace1e24dd"
    "6d48120fc9704cd363883a170600000038ec8b0f7ffe3ae75d7ffab09429e367"
    "5bb63503e418556e697377617020556e6976657273616c20526f757465720100"
    "0000008097d9e9c94f5e03c18e328c25fee813a9a58b95a1d62bceb9c3289b12"
    "e228d208448dc499cc9f5b7b19dc2eee58c0b2e399b6203654176350e742cbec"
    "fc12949f00")
USDC = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
COW_APPROVE = bytes.fromhex(
    "095ea7b3000000000000000000000000c92e8bdf79f0507f65a392b0ab4667716bfe0110"
    "00000000000000000000000000000000000000000000000000000005d21dba00")


def approve_to(spender_hex):
    return COW_APPROVE[:16] + bytes.fromhex(spender_hex) + COW_APPROVE[36:]


UR_APPROVE = approve_to("66a9893cc07d91d95644aedd05d03f95e1dba8af")
BSC_UR_APPROVE = approve_to("ec8b0f7ffe3ae75d7ffab09429e3675bb63503e4")
PROVENANCE = ("Spender named by KeepKey ClearSign FDD258EC\n"
              "certified by KeepKey")


class TestEthereumApproveNames(common.KeepKeyTest):

    def setUp(self):
        super(TestEthereumApproveNames, self).setUp()
        self.requires_firmware("7.17.0")
        self.requires_message("EthereumTxMetadata")
        self.setup_mnemonic_allallall()

    def _approve(self, data, record=None):
        if record is not None:
            resp = self.client.ethereum_send_tx_metadata(
                signed_payload=record, metadata_version=3, key_id=0x80)
            self.assertEqual(resp.classification, 1)  # VERIFIED
        recorder = ScreenRecorder(self.client, answer=True,
                                  screenshot_group="eth-approve-names")
        with recorder:
            sig = self.client.ethereum_sign_tx(
                n=parse_path("m/44'/60'/0'/0/0"), nonce=7, gas_limit=60000,
                max_fee_per_gas=0xd52bef138, max_priority_fee_per_gas=10**9,
                value=0, to=USDC, data=data, chain_id=1)
        return sig, recorder.screens

    def _titled(self, screens, title):
        return [s for s in screens
                if find_line(s, title, TITLE_FONT) is not None]

    def test_vouched_spender_is_named_beside_its_address(self):
        plain_sig, plain = self._approve(UR_APPROVE)
        sig, screens = self._approve(UR_APPROVE, ETH_UR_NAME)
        self.assertEqual(sig, plain_sig)  # nothing signed changes
        # The named approve, then who named it, then the fee screen.
        self.assertEqual(screens[-1], plain[-1])
        # confirm() pages the body: the name and full address span 1/2, 2/2.
        self.assertTrue(shows(
            screens[0], "Approve withdrawal of up to 25000 USDC by Uniswap "
                        "Universal Router (0x66a9893cC07D91D95644AEDD05D03f95e"
                        "1dB"))
        self.assertTrue(shows(screens[1], "A8Af)?"))
        self.assertTrue(shows(
            plain[0], "Approve withdrawal of up to 25000 USDC by "
                      "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af?"))
        vouched = self._titled(screens, "KEEPKEY CLEARSIGN")
        self.assertEqual(len(vouched), 1)
        self.assertIs(vouched[0], screens[-2])
        self.assertTrue(shows(vouched[0], PROVENANCE))
        self.assertEqual(self._titled(plain, "KEEPKEY CLEARSIGN"), [])
        # One request per record: the next approve is not named.
        _, again = self._approve(UR_APPROVE)
        self.assertEqual(again, plain)

    def test_name_for_another_spender_is_ignored(self):
        plain_sig, plain = self._approve(COW_APPROVE)
        sig, screens = self._approve(COW_APPROVE, ETH_UR_NAME)
        self.assertEqual(sig, plain_sig)
        self.assertEqual(screens, plain)

    def test_name_for_another_chain_is_ignored(self):
        plain_sig, plain = self._approve(BSC_UR_APPROVE)
        sig, screens = self._approve(BSC_UR_APPROVE, BSC_UR_NAME)
        self.assertEqual(sig, plain_sig)
        self.assertEqual(screens, plain)

    def test_malformed_name_record_refuses_the_approve(self):
        bad = bytearray(ETH_UR_NAME)
        bad[-10] ^= 1  # inside the delegate's signature
        resp = self.client.ethereum_send_tx_metadata(
            signed_payload=bytes(bad), metadata_version=3, key_id=0x80)
        self.assertEqual(resp.classification, 2)  # MALFORMED
        with self.assertRaises(CallException) as e:
            self._approve(UR_APPROVE)
        self.assertEqual(e.exception.args[1],
                         "Certified description invalid or not for this tx")


if __name__ == '__main__':
    unittest.main()
