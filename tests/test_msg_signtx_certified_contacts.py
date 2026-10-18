# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Certified contacts for Bitcoin-family coins.

The user certifies contacts on the device as for EVM, but each one is an exact
output script bound to one coin by its CAIP-2 network. A later SignTx carries
one contact's proof in contact_proof. An output paying that script on that
coin reads "Send <amount> to <name>", with the full address below it. A proof
the device cannot use is ignored, and the transaction is reviewed and signed
as usual.

The request, commitment and proof are built here from the format alone, and
the device's signature is checked with python-ecdsa. The inputs use made-up
outpoints: the device never asks for a segwit input's previous transaction.
"""

import hashlib
import unittest

import common
import oled_text

from ecdsa import SECP256k1, VerifyingKey, util

from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib.tools import parse_path

BTC = "bip122:000000000019d6689c085ae165831e93"
TESTNET = "bip122:000000000933ea01ad0ee984209779ba"
BCH = "bip122:000000000000000000651ef99cb9fcbe"

ALICE = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
BOB = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
CAROL = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
DAVE = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
ERIN = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
TESS = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"  # Alice's script on Testnet
CAROL_BCH = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"

H20 = "751e76e8199196d454941c45d1b3a323f1433bd6"
SCRIPTS = {
    ALICE: "0014" + H20,
    BOB: "5120" + "79be667ef9dcbbac55a06295ce870b07"
                  "029bfcdb2dce28d959f2815b16f81798",
    CAROL: "76a914" + "76a04053bda0a88bda5177b86a15c3b29f559873" + "88ac",
    DAVE: "a914" + "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb" + "87",
    ERIN: "0020" + "1863143c14c5166804bd19203356da13"
                   "6c985678cd4d27a1b8c6329604903262",
}
OUTPUT_TYPE = {
    ALICE: types.PAYTOWITNESS, BOB: types.PAYTOTAPROOT,
    CAROL: types.PAYTOADDRESS, DAVE: types.PAYTOSCRIPTHASH,
    ERIN: types.PAYTOWITNESS, TESS: types.PAYTOWITNESS,
    CAROL_BCH: types.PAYTOADDRESS,
}

BOOK = ((BTC, ALICE, "Alice"), (BTC, BOB, "Bob"), (BTC, CAROL, "Carol"),
        (BTC, DAVE, "Dave"), (BTC, ERIN, "Erin"))
REVISION = 4


def _entry(network, address, label):
    net, name = network.encode(), label.encode()
    dest = bytes.fromhex(SCRIPTS[address])
    return (bytes([len(net)]) + net + bytes([2, len(dest)]) + dest
            + bytes([len(name)]) + name)


def _sha(data):
    return hashlib.sha256(data).digest()


def _levels(book):
    """Merkle levels, leaves first; a short level repeats its last leaf."""
    level = [_sha(b"KKABLEAF" + _entry(*c)) for c in book]
    width = 1
    while width < len(level):
        width *= 2
    level += [level[-1]] * (width - len(level))
    levels = [level]
    while len(level) > 1:
        level = [_sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def _header(book, revision):
    return b"\x01" + revision.to_bytes(4, "big") + bytes([len(book)])


def request(book, revision=REVISION):
    return (b"KKABREQ1" + _header(book, revision)
            + b"".join(_entry(*c) for c in book))


def manifest(book, revision=REVISION):
    return b"KKABRT01" + _header(book, revision) + _levels(book)[-1][0]


def proof(book, index, public_key, signature, revision=REVISION):
    levels = _levels(book)
    siblings, cursor = [], index
    for level in levels[:-1]:
        siblings.append(level[cursor ^ 1])
        cursor >>= 1
    return (b"KKABPRF1" + _header(book, revision) + levels[-1][0] + public_key
            + signature + _entry(*book[index])
            + bytes([index, len(siblings)]) + b"".join(siblings))


def _out(address, amount):
    return types.TxOutputType(address=address, amount=amount,
                              script_type=OUTPUT_TYPE[address])


class TestMsgSigntxCertifiedContacts(common.KeepKeyTest):

    def setUp(self):
        super(TestMsgSigntxCertifiedContacts, self).setUp()
        self.requires_release_capability("certified-contacts-utxo")
        self.setup_mnemonic_allallall()

    def _capturing(self, fn):
        """Run fn() approving every screen; return (screens, result)."""
        screens = []
        press = self.client.callback_ButtonRequest

        def capture(req):
            screens.append(self.client._read_oled_after_settle())
            return press(req)

        self.client.callback_ButtonRequest = capture
        try:
            result = fn()
        finally:
            del self.client.callback_ButtonRequest
        return screens, result

    def _certify(self, book=BOOK):
        screens, resp = self._capturing(lambda: self.client.call(
            proto.ClearsignAttestorSign(payload=request(book))))
        self.assertIsInstance(resp, proto.ClearsignAttestorSignature)
        return screens, resp.public_key, resp.signature

    def _proof(self, index, book=BOOK):
        _, public_key, signature = self._certify(book)
        return proof(book, index, public_key, signature)

    def _sign(self, outputs, contact_proof=None, coin="Bitcoin", change=True):
        """A 0.01 BTC segwit input; `outputs`, then change unless told not."""
        purpose_coin = {"Bitcoin": "84'/0'", "Testnet": "84'/1'"}[coin]
        inputs = [types.TxInputType(
            address_n=parse_path(purpose_coin + "/0'/0/0"), amount=1000000,
            prev_hash=bytes([0xA1]) * 32, prev_index=0,
            script_type=types.SPENDWITNESS)]
        outputs = list(outputs)
        if change:
            spent = sum(o.amount for o in outputs)
            outputs.append(types.TxOutputType(
                address_n=parse_path(purpose_coin + "/0'/1/0"),
                amount=1000000 - spent - 1000,
                script_type=types.PAYTOWITNESS))
        return self._capturing(lambda: self.client.sign_tx(
            coin, inputs, outputs, contact_proof=contact_proof))

    def _shown(self, screens, text):
        return [i for i, s in enumerate(screens) if oled_text.shows(s, text)]

    def test_certifying_shows_each_contact_as_its_coins_address(self):
        # No AdvancedMode: the user reviews their own contacts.
        screens, public_key, signature = self._certify()

        # One summary, then a name screen and an address screen per contact.
        self.assertEqual(len(screens), 1 + 2 * len(BOOK))
        self.assertTrue(oled_text.shows(
            screens[0], "Approve 5 contacts?\nRevision 4"))
        for i, (_, address, label) in enumerate(BOOK):
            with self.subTest(label):
                self.assertTrue(oled_text.shows(
                    screens[1 + 2 * i], "%s\nBitcoin" % label))
                self.assertTrue(oled_text.shows(screens[2 + 2 * i], address))

        key = VerifyingKey.from_string(public_key, curve=SECP256k1)
        self.assertTrue(key.verify_digest(
            signature, _sha(manifest(BOOK)), sigdecode=util.sigdecode_string))

    def test_a_payment_to_a_contact_names_it_beside_the_full_address(self):
        baseline, (_, signed) = self._sign([_out(ALICE, 100000)])
        self.assertEqual(
            len(self._shown(baseline, "Send 0.001 BTC to\n" + ALICE)), 1)

        named, (_, named_tx) = self._sign([_out(ALICE, 100000)],
                                          self._proof(0))
        # The same review, one screen changed: the name, then the full address.
        self.assertEqual(len(named), len(baseline))
        self.assertEqual(
            len(self._shown(named, "Send 0.001 BTC to Alice\n" + ALICE)), 1)
        self.assertEqual(self._shown(named, "Send 0.001 BTC to\n" + ALICE), [])
        # The proof changes the screen, never the transaction.
        self.assertEqual(named_tx, signed)

        # One proof names one transaction: the next one is the baseline again.
        again, _ = self._sign([_out(ALICE, 100000)])
        self.assertEqual(len(again), len(baseline))
        self.assertEqual(self._shown(again, "Send 0.001 BTC to Alice\n" + ALICE),
                         [])

    def test_every_script_type_is_named_and_only_its_own_output(self):
        outputs = [_out(address, 10000 * (i + 1))
                   for i, (_, address, _) in enumerate(BOOK)]
        _, public_key, signature = self._certify()
        for index, (_, address, label) in enumerate(BOOK):
            with self.subTest(label):
                screens, _ = self._sign(
                    outputs, proof(BOOK, index, public_key, signature))
                amount = "0.000%d BTC" % (index + 1)
                self.assertEqual(len(self._shown(
                    screens, "Send %s to %s\n%s" % (amount, label, address))), 1)
                for other, (_, other_address, other_label) in enumerate(BOOK):
                    if other == index:
                        continue
                    other_amount = "0.000%d BTC" % (other + 1)
                    self.assertEqual(self._shown(screens, "Send %s to %s" % (
                        other_amount, other_label)), [])

    def test_change_and_data_outputs_are_never_named(self):
        memo = types.TxOutputType(amount=0, op_return_data=b"hello",
                                  script_type=types.PAYTOOPRETURN)
        outputs = [_out(ALICE, 100000), _out(BOB, 20000), memo,
                   _out(ALICE, 30000)]
        baseline, _ = self._sign(outputs)
        named, _ = self._sign(outputs, self._proof(0))
        self.assertEqual(len(named), len(baseline))
        # Both outputs paying Alice are named; Bob, the memo and the change
        # (never shown) are as before.
        self.assertEqual(len(self._shown(
            named, "Send 0.001 BTC to Alice\n" + ALICE)), 1)
        self.assertEqual(len(self._shown(
            named, "Send 0.0003 BTC to Alice\n" + ALICE)), 1)
        self.assertEqual(len(self._shown(named, "Send 0.0002 BTC to\n" + BOB)),
                         1)
        for i, screen in enumerate(baseline):
            if not oled_text.shows(screen, "Send 0.001 BTC to\n" + ALICE) and \
                    not oled_text.shows(screen, "Send 0.0003 BTC to\n" + ALICE):
                with self.subTest("screen %d" % i):
                    self.assertEqual(named[i], screen)

    def test_an_unusable_proof_is_ignored_and_the_payment_still_signs(self):
        baseline, (_, signed) = self._sign([_out(ALICE, 100000)])
        _, public_key, signature = self._certify()
        good = proof(BOOK, 0, public_key, signature)
        label_at = good.index(b"Alice")
        cases = {
            "an altered name": good[:label_at] + b"Alicf" + good[label_at + 5:],
            "an altered signature": good.replace(
                signature, signature[:-1] + bytes([signature[-1] ^ 1])),
            "another book": proof(BOOK[:2], 0, public_key, signature),
            "Bob's proof": proof(BOOK, 1, public_key, signature),
            "not a proof": b"KKABPRF1",
        }
        for name, bad in cases.items():
            with self.subTest(name):
                screens, (_, tx) = self._sign([_out(ALICE, 100000)], bad)
                self.assertEqual(len(screens), len(baseline))
                self.assertEqual(self._shown(screens, "Send 0.001 BTC to Alice"),
                                 [])
                self.assertEqual(tx, signed)

    def test_a_contact_names_only_its_own_coin(self):
        # Alice's script is a Testnet address too; her contact is on Bitcoin.
        alice = self._proof(0)
        baseline, _ = self._sign([_out(TESS, 100000)], coin="Testnet")
        screens, _ = self._sign([_out(TESS, 100000)], alice, coin="Testnet")
        self.assertEqual(len(screens), len(baseline))
        self.assertEqual(len(self._shown(
            screens, "Send 0.001 TEST to\n" + TESS)), 1)

    def test_a_bitcoin_contact_never_names_the_same_script_on_bitcoin_cash(self):
        self.requires_fullFeature()
        carol = self._proof(2)
        inputs = [types.TxInputType(
            address_n=parse_path("44'/145'/0'/0/0"), amount=1000000,
            prev_hash=bytes([0xB2]) * 32, prev_index=0,
            script_type=types.SPENDADDRESS)]
        screens, _ = self._capturing(lambda: self.client.sign_tx(
            "BitcoinCash", inputs, [_out(CAROL_BCH, 900000)],
            contact_proof=carol))
        self.assertEqual(self._shown(screens, "Send 0.009 BCH to Carol"), [])
        self.assertEqual(len(self._shown(
            screens, "Send 0.009 BCH to\n" + CAROL_BCH)), 1)

        # Certified for Bitcoin Cash, the same script is named there.
        carol_cash = self._proof(0, ((BCH, CAROL, "Carol cash"),))
        screens, _ = self._capturing(lambda: self.client.sign_tx(
            "BitcoinCash", inputs, [_out(CAROL_BCH, 900000)],
            contact_proof=carol_cash))
        self.assertEqual(len(self._shown(
            screens, "Send 0.009 BCH to Carol cash\n" + CAROL_BCH)), 1)

    def test_a_book_the_device_cannot_show_is_refused_unreviewed(self):
        bad = {
            "a data script": ((BTC, "6a0568656c6c6f", "Data"),),
            "a network no coin is bound to": (
                ("bip122:00000000000000000000000000000000", ALICE, "Alice"),),
            "one name, two scripts": ((BTC, ALICE, "Alice"),
                                      (BTC, BOB, "Alice")),
        }
        for name, book in bad.items():
            with self.subTest(name):
                entries = []
                for network, script_or_address, label in book:
                    script = bytes.fromhex(
                        SCRIPTS.get(script_or_address, script_or_address))
                    net, lab = network.encode(), label.encode()
                    entries.append(bytes([len(net)]) + net
                                   + bytes([2, len(script)]) + script
                                   + bytes([len(lab)]) + lab)
                payload = (b"KKABREQ1" + _header(book, REVISION)
                           + b"".join(entries))
                # call_raw answers nothing: a ButtonRequest here would mean
                # the device started a review.
                resp = self.client.call_raw(
                    proto.ClearsignAttestorSign(payload=payload))
                self.assertIsInstance(resp, proto.Failure)
                self.assertEqual(resp.code, types.Failure_SyntaxError)
                self.assertEqual(resp.message, "Invalid address book")


if __name__ == '__main__':
    unittest.main()
