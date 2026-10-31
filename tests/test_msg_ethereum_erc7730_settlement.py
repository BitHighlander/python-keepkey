"""Seaport phishing protection: what the signer receives (7.17).

A drainer site asks the victim to sign a Seaport order that gives away the
victim's NFT and pays the victim nothing (one wei to a stranger, or the real
payments with the seller's own payment redirected), or a payment that only
looks like one: one wei, or a token the attacker made. Through 7.17's first
Seaport definition every such order signed under "Verified by KeepKey" with
the same calm screens as a real listing.

A typed-data definition may now opt in to a settlement review: it marks the
field of each item the order gives away ("settlement": "give") and the type,
identifier, amounts and recipient of each item it pays out ("type", "id",
"amount", "to"). The device keeps what is paid to the signing address it
derives itself and, after the definition's last field, shows it on a screen
the definition cannot change or skip: "You receive" with the totals, or
"WARNING" when this wallet receives nothing, or only unknown tokens, NFTs or
dust for what it gives. What is signed never changes, and every value is
still shown exactly once.

An item whose type is marked is also shown as Seaport moves it: an NFT
item's amount reads as its identifier and count ("NFT ID 446", "2 of NFT ID
650", "1 NFT by criteria"), never as an amount of its token, because Seaport
moves an ERC-721 item by its identifier whatever its token is. An NFT item
naming a coin of the firmware's table (an ERC-721 "WETH" moves its identifier
in wei of WETH) makes the last screen a warning. Offer items may carry the
same type, identifier and amount roles as payments; with no recipient they
count as given. The other way round, Seaport moves an ERC-20 item with
transferFrom(from, to, amount), which an ERC-721 answers too: an ERC-20 item
naming an NFT collection gives the NFT whose ID is the amount. So giving an
ERC-20 the table does not list on the chain makes the last screen a warning.

Dust is counted in units, not value: under a millionth of one coin, or under
a hundredth of one for six decimals or fewer (one base unit of USDC is dust).

Wallets compared (2026-10): Ledger and Trezor show the typed-data fields and
have no on-device rule over who is paid in a Seaport order; Blockaid
(MetaMask), Pocket Universe and Rabby simulate the order on the host and warn
there. This check runs on the device, from the signed bytes.

Real orders: thirteen OpenSea Seaport 1.6 listings rebuilt from their
fulfillBasicOrder fills (order hash equals the OrderFulfilled event, the
signature recovers the offerer), as this wallet would sign them: the offerer
and the seller's payment are this wallet. The phishing orders are derived
from them. The device signs with the "abandon" test mnemonic; signatures are
compared with plain streaming, and the definition is signed by the throwaway
runtime key (AdvancedMode, "NOT verified by KeepKey").
"""

import copy
from decimal import Decimal

import common
from keepkeylib import erc7730, erc7730_compiler
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import types_pb2 as types
from test_msg_ethereum_erc7730_runtime import Erc7730Harness, assert_failure
from test_msg_ethereum_erc7730_typed_iteration import (
    CREATOR, CREATOR_FEE, LISTING, OPENSEA_FEE, ORDER_FORMAT, PATH,
    SEAPORT_DOMAIN, SEAPORT_TYPES, ZERO, ZERO32)

# The "abandon ... about" mnemonic at m/44'/60'/0'/0/0.
SIGNER = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
STRANGER = "0x00000000000000000000000000000000DeaDBeef"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
WORTHLESS = "0x1111111111111111111111111111111111111111"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
CONDUIT = "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000"
SELLER = "seller"  # the real offerer: this wallet in every test

REAL_ORDERS = [
    # 0x6a99d606f13ab4379635426908cdbcc0dd8d04aa510a9dc8e76ff7e53281a9ce
    (137, [(3, '0x22d5f9B75c524Fec1D6619787e582644CD4D7422', '446', '1')],
     [(1, '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619', '3613500000000000', SELLER),
      (1, '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619', '36500000000000', OPENSEA_FEE)],
     0, '1793306151', '1793910951',
     '27855337018906766782546881864045825683096516384821792734234868703509530967094',
     '0'),
    # 0x5b7c66b708716a7138cfd0ddb3f2329b542592b6eb9d72f4e307d1f6deb734cd
    (137, [(2, '0x251BE3A17Af4892035C37ebf5890F4a4D889dcAD', '34359448840295777673655050614723288121325103585739033537781777436162294190250', '1')],
     [(1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '13206000', SELLER),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '142000', OPENSEA_FEE),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '852000', '0x732134D7f99b90C704d736B360dB45425073380f')],
     0, '1793396070', '1798580070',
     '27855337018906766782546881864045825683096516384821792734247637289137771993225',
     '0'),
    # 0x3adf19be32efec69cd9440299f763cca49fb129c6fa3393b7e33c504fcf2eb64
    (137, [(2, '0x251BE3A17Af4892035C37ebf5890F4a4D889dcAD', '60105492021038956789376004874433832340660385680807576982244478177608196469233', '1')],
     [(1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '23250000', SELLER),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '250000', OPENSEA_FEE),
      (1, '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', '1500000', '0x732134D7f99b90C704d736B360dB45425073380f')],
     0, '1793394838', '1793398438',
     '27855337018906766782546881864045825683096516384821792734239831000570884848736',
     '0'),
    # 0x529284af5624ef9907cb59fce6528deeb464cbc15f8604957ce70cdf7add7908
    (42161, [(2, '0xC227e25544EdD261A9066932C71a25F4504972f1', '10925', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '51965100000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '524900000000000', OPENSEA_FEE)],
     0, '1793388508', '1801164508',
     '27855337018906766782546881864045825683096516384821792734238018274238790998880',
     '0'),
    # 0xf6592a9d697431fed763548254b96e645cb14981d267874977d814c304d74f8e
    (42161, [(2, '0xC227e25544EdD261A9066932C71a25F4504972f1', '51611', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '51876000000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '524000000000000', OPENSEA_FEE)],
     0, '1793337530', '1801113530',
     '27855337018906766782546881864045825683096516384821792734249439184772095363824',
     '0'),
    # 0xd0d26059399cc15d4adc71126007a6fcfa6e9a8180d3907773703979d72e08b5
    (43114, [(3, '0xa695ea0C90D89a1463A53Fa7a02168Bc46FbBF7e', '650', '2')],
     [(0, '0x0000000000000000000000000000000000000000', '55242000000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '558000000000000', OPENSEA_FEE)],
     1, '1793025427', '1793630227',
     '44352388033253391722174868795062602107181742468261888849129876456468951810407',
     '160192324572955410065383452032537714378'),
    # 0xc27875074f7e1e3a2f18d3077c2e548d5e3c537f8f818ef0cf5f4e12ec97fb26
    (43114, [(3, '0xa695ea0C90D89a1463A53Fa7a02168Bc46FbBF7e', '370', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '67679060000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '719990000000000', OPENSEA_FEE),
      (0, '0x0000000000000000000000000000000000000000', '3599950000000000', '0x6F27aA71Ee313F39D2071dE0554cE55900148184')],
     0, '1793396575', '1801172575',
     '27855337018906766782546881864045825683096516384821792734236904970083784339576',
     '0'),
    # 0x61f5a0971954c7b35750f05e85ecbcf035330db4ae4997ecb24334bbf1d1b64d
    (43114, [(3, '0xa695ea0C90D89a1463A53Fa7a02168Bc46FbBF7e', '250', '2')],
     [(0, '0x0000000000000000000000000000000000000000', '29502000000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '298000000000000', OPENSEA_FEE)],
     1, '1793318538', '1793923338',
     '47116205494824075209979464729591148675478147799213783147724356185403060327312',
     '160192324572955410065383452032537714378'),
    # 0xa6ac44a7546bb1cf4ff927cf39b6bf5d47e5df1cb01bc24e8463bf7b2d437eb0
    (8453, [(2, '0xEB485363a50198B14589107c296A0d8a70479c08', '3', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '25000000000000', SELLER)],
     0, '1793407456', '1793414656',
     '1793407516274553',
     '0'),
    # 0x04c7c59ba10478fbd43224714d4f3841b6f6cc37e47270ca2f5867bcd601a295
    (8453, [(2, '0xEB485363a50198B14589107c296A0d8a70479c08', '2', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '19800000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '200000000000', OPENSEA_FEE)],
     0, '1793407014', '1793414214',
     '1793407134058854',
     '0'),
    # 0xbe11a1aaca3e1685f9d1b3cac86dbdf87c98e1f67d70b708b0251e9b2e7af8e7
    (8453, [(2, '0xEB485363a50198B14589107c296A0d8a70479c08', '1', '1')],
     [(0, '0x0000000000000000000000000000000000000000', '22250000000000', SELLER),
      (0, '0x0000000000000000000000000000000000000000', '250000000000', OPENSEA_FEE),
      (0, '0x0000000000000000000000000000000000000000', '2500000000000', '0x036CdBD5d44524e796029E54eDCb1576e129592F')],
     0, '1793406712', '1793579512',
     '27855337018906766782546881864045825683096516384821792734240101351710316449337',
     '0'),
]


def _role(roles, name, params=None):
    params = dict(params or {})
    if roles:
        params["settlement"] = name
    return params


def _item_fields(prefix, roles, give, described):
    """Seaport item fields, as batch 6-D's definition shows them. An offer
    item carries one "give", or with `described` the type, identifier and
    amount roles a payment carries (it has no recipient, so it is given)."""
    item_roles = roles and (described or not give)

    def amount(path, label):
        return {"path": path, "label": label, "format": "tokenAmount",
                "params": _role(item_roles, "amount", {
                    "tokenPath": "token", "nativeCurrencyAddress": [ZERO]})}
    return [
        {"path": "itemType", "label": prefix + " type", "format": "enum",
         "params": _role(roles, "type" if item_roles else "give",
                         {"$ref": "$.metadata.enums.itemType"})},
        {"path": "identifierOrCriteria", "label": prefix + " ID/criteria",
         "format": "raw", "params": _role(item_roles, "id")},
        amount("startAmount", prefix + " amount"),
        amount("endAmount", prefix + " end amount")]


def seaport_descriptor(roles=True, described=False):
    """The Seaport 1.6 OrderComponents definition; with `roles`, its fields
    carry their settlement roles (with `described`, offer items too)."""
    return {
        "metadata": {"owner": "OpenSea", "enums": {
            "itemType": {"0": "Native coin", "1": "ERC-20",
                         "2": "NFT (ERC-721)", "3": "ERC-1155",
                         "4": "ERC-721 by criteria",
                         "5": "ERC-1155 by criteria"},
            "orderType": {"0": "Full, open", "1": "Partial, open",
                          "2": "Full, restricted", "3": "Partial, restricted",
                          "4": "Contract order"}}},
        "display": {"formats": {ORDER_FORMAT: {
            "intent": "Seaport order",
            "fields": [
                {"path": "offerer", "label": "Offerer",
                 "format": "addressName"},
                {"path": "offer.[]", "label": "You give",
                 "fields": _item_fields("Give", roles, True, described)},
                {"path": "consideration.[]", "label": "Paid out",
                 "fields": _item_fields("Payment", roles, False,
                                        described) + [
                     {"path": "recipient", "label": "Paid to",
                      "format": "addressName",
                      "params": _role(roles, "to", {"recipient": True})}]},
                {"path": "startTime", "label": "Starts", "format": "date",
                 "params": {"encoding": "timestamp"}},
                {"path": "endTime", "label": "Expires", "format": "date",
                 "params": {"encoding": "timestamp"}},
                {"path": "orderType", "label": "Order type", "format": "enum",
                 "params": {"$ref": "$.metadata.enums.orderType"}},
                {"path": "zone", "label": "Zone", "format": "addressName"},
                {"path": "zoneHash", "label": "Zone hash", "format": "raw"},
                {"path": "conduitKey", "label": "Conduit key",
                 "format": "raw"},
                {"path": "salt", "label": "Salt", "format": "raw"},
                {"path": "counter", "label": "Counter", "format": "raw"}]}}}}


def _real(order):
    chain, offer, consideration, order_type, start, end, salt, counter = order
    return {
        "types": SEAPORT_TYPES,
        "primaryType": "OrderComponents",
        "domain": dict(SEAPORT_DOMAIN, chainId=chain),
        "message": {
            "offerer": SIGNER,
            "zone": ZERO,
            "offer": [{"itemType": t, "token": token,
                       "identifierOrCriteria": i, "startAmount": a,
                       "endAmount": a} for t, token, i, a in offer],
            "consideration": [
                {"itemType": t, "token": token, "identifierOrCriteria": "0",
                 "startAmount": a, "endAmount": a,
                 "recipient": SIGNER if to == SELLER else to}
                for t, token, a, to in consideration],
            "orderType": order_type,
            "startTime": start,
            "endTime": end,
            "zoneHash": ZERO32,
            "salt": salt,
            "conduitKey": CONDUIT,
            "counter": counter}}


def _as_signer(doc):
    """A real mainnet listing as this wallet would sign it."""
    doc = copy.deepcopy(doc)
    seller = doc["message"]["offerer"]
    doc["message"]["offerer"] = SIGNER
    for item in doc["message"]["consideration"]:
        if item["recipient"] == seller:
            item["recipient"] = SIGNER
    return doc


def _paid(doc, *items):
    """`doc` paying `items` instead: (itemType, token, amount, recipient[,
    end amount[, identifier]])."""
    doc = copy.deepcopy(doc)
    doc["message"]["consideration"] = [
        {"itemType": item[0], "token": item[1],
         "identifierOrCriteria": item[5] if len(item) > 5 else "0",
         "startAmount": item[2],
         "endAmount": item[4] if len(item) > 4 else item[2],
         "recipient": item[3]} for item in items]
    return doc


MAINNET = [_as_signer(LISTING), _as_signer(CREATOR_FEE)]
NATIVE = {1: "ETH", 8453: "ETH", 42161: "ETH", 43114: "AVAX"}
DUST = "This wallet gets only unknown tokens, NFTs or dust:\n"
NOTHING = ("WARNING", "Nothing in this order is paid to this wallet.")
COIN_WETH = ("An NFT item names the token WETH: Seaport moves its ID as an "
             "amount of WETH.\n")
NFT = LISTING["message"]["offer"][0]["token"]
GIVES_UNKNOWN = ("This wallet gives a token the device does not know: if it "
                 "is an NFT collection, Seaport moves the NFT whose ID is the "
                 "amount.\n")


def _native(amount, chain):
    """The device's own rendering of a native amount."""
    if amount < 10 ** 9:
        return "%d Wei" % amount
    return "%s %s" % (format((Decimal(amount) / 10 ** 18).normalize(), "f"),
                      NATIVE[chain])


def _expected(doc):
    """The settlement screen a real listing gets, from the order alone: the
    seller's one payment, in the native coin (calm) or in a token this
    firmware's table does not list on that chain (a warning)."""
    chain = doc["domain"]["chainId"]
    mine = [item for item in doc["message"]["consideration"]
            if item["recipient"] == SIGNER]
    assert len(mine) == 1
    amount = int(mine[0]["startAmount"])
    if mine[0]["itemType"] == 0:
        return ("You receive", _native(amount, chain))
    return ("WARNING", "%s%d\nunknown token\n%s" % (DUST, amount,
                                                     mine[0]["token"]))


class TestMsgEthereumErc7730Settlement(Erc7730Harness, common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.requires_fullFeature()
        self.requires_firmware("7.17.0")
        self.requires_release_capability("erc7730-runtime-review")
        self.requires_release_capability("erc7730-typed-iteration")
        self.requires_release_capability("erc7730-typed-settlement")
        self.requires_structured_eip712()
        self.setup_mnemonic_abandon()
        self.client.apply_policy("AdvancedMode", 1)
        self.assertEqual(self.client.ethereum_get_address(PATH),
                         bytes.fromhex(SIGNER[2:]))

    def _start(self, doc):
        return eth.EthereumSignTypedData(
            address_n=PATH, primary_type=doc["primaryType"],
            metamask_v4_compat=True)

    def _sign(self, doc, descriptor=None, cancel_title=None):
        """Sign `doc` streamed, then with its definition (the settlement one
        by default). Returns the certified pages; the signature must be
        streaming's, or the response a Failure when `cancel_title` declines."""
        baseline, _, _, _ = self._walk(self._start(doc), doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        chain = doc["domain"]["chainId"]
        program = erc7730_compiler.compile_eip712(
            descriptor or seaport_descriptor(), doc)
        self._load_signer()
        envelope = self._envelope(program, chain=chain)
        erc7730.preload(self.client, self._definition(program, envelope))
        self._drop_setup_screenshots()
        result, _, _, _ = self._walk(self._start(doc), envelope, doc,
                                     cancel_title=cancel_title)
        if cancel_title:
            self.result = result
            return self.screens
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        return self._first_pages()

    def _settlement(self, doc, descriptor=None):
        """The settlement screen(s) of `doc`, after checking where they are:
        right after the definition's last field."""
        pages = self._sign(doc, descriptor)
        shown = [(title, body) for title, body in pages
                 if title in ("You receive", "WARNING")]
        if shown:
            fields = [i for i, (title, _) in enumerate(pages)
                      if title.startswith("Signer field")]
            self.assertEqual(pages.index(shown[0]), fields[-1] + 1)
        return shown

    def test_real_listings_show_what_this_wallet_receives(self):
        # Paid in the native coin: calm. Paid in Polygon WETH or USDC.e: a
        # warning, because this firmware's token table lists no Polygon
        # token (a table limit; the device cannot tell them from a token an
        # attacker made).
        for order in MAINNET + [_real(o) for o in REAL_ORDERS]:
            message = order["message"]
            with self.subTest(chain=order["domain"]["chainId"],
                              salt=message["salt"][-8:]):
                self.assertEqual(self._settlement(order), [_expected(order)])

    def test_every_value_is_still_shown_once(self):
        # The roles add one screen and change nothing else: the same pages,
        # in the same order, as the same definition without roles.
        doc = MAINNET[1]
        with_roles = self._sign(doc)
        without = self._sign(doc, seaport_descriptor(roles=False))
        added = ("You receive", "0.01974 ETH")
        self.assertIn(added, with_roles)
        self.assertNotIn(added, without)
        self.assertEqual([p for p in with_roles if p != added], without)
        self.assertEqual(
            [t for t, _ in with_roles if t == "EIP-712 Message"], [])

    def test_one_wei_to_a_stranger_warns(self):
        self.assertEqual(self._settlement(
            _paid(MAINNET[0], (0, ZERO, "1", STRANGER))), [NOTHING])

    def test_a_redirected_payment_warns(self):
        # The real creator-fee listing, the seller's payment sent elsewhere:
        # every payment goes to another address.
        doc = copy.deepcopy(MAINNET[1])
        doc["message"]["consideration"][0]["recipient"] = STRANGER
        self.assertEqual(self._settlement(doc), [NOTHING])

    def test_an_order_from_another_wallet_pays_this_wallet_nothing(self):
        # The real listing unchanged: its seller is not this wallet.
        self.assertEqual(self._settlement(LISTING), [NOTHING])

    def test_one_wei_to_this_wallet_warns(self):
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (0, ZERO, "1", SIGNER),
            (0, ZERO, "5589978100000000", OPENSEA_FEE))),
            [("WARNING", DUST + "1 Wei")])

    def test_a_worthless_token_payment_warns(self):
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (1, WORTHLESS, "1000000000000000000000", SIGNER),
            (0, ZERO, "5589978100000000", OPENSEA_FEE))),
            [("WARNING", DUST + "1000000000000000000000\nunknown token\n" +
              WORTHLESS)])

    def test_a_dutch_auction_counts_its_smaller_amount(self):
        # Starts at 0.55 ETH, ends at 1 wei: the order can settle for 1 wei.
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (0, ZERO, "553407831900000000", SIGNER, "1"))),
            [("WARNING", DUST + "1 Wei")])

    def test_an_nft_item_naming_weth_is_not_weth(self):
        # Seaport moves an ERC-721 item by its identifier (1 wei here),
        # whatever its token: it is never counted as WETH, and no NFT is a
        # coin of the firmware's table.
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (2, WETH, "1", SIGNER, "1", "1"))),
            [("WARNING", COIN_WETH + DUST + "NFT ID 1\n" + WETH)])

    def _amounts(self, pages):
        return [body for _, body in pages
                if body.split(":\n", 1)[0].endswith("amount")]

    def test_items_are_shown_as_seaport_moves_them(self):
        # Offer items marked like payments: every amount reads by its item
        # type. An NFT is its identifier and count, never an amount of its
        # token; coins keep their token amount.
        doc = _paid(MAINNET[0], (0, ZERO, "19740000000000000", SIGNER),
                    (1, WETH, "210000000000000", OPENSEA_FEE),
                    (3, NFT, "4", SIGNER, "4", "7"))
        doc["message"]["offer"] = [
            {"itemType": t, "token": NFT, "identifierOrCriteria": i,
             "startAmount": a, "endAmount": a}
            for t, i, a in ((2, "446", "1"), (3, "650", "2"), (5, "9", "7"))]
        pages = self._sign(doc, seaport_descriptor(described=True))
        shown = []
        for label, value in (
                ("Give", "NFT ID 446\n" + NFT),
                ("Give", "2 of NFT ID 650\n" + NFT),
                ("Give", "7 NFT by criteria\n" + NFT),
                ("Payment", "0.01974 ETH"), ("Payment", "0.00021 WETH"),
                ("Payment", "4 of NFT ID 7\n" + NFT)):
            shown += ["%s amount:\n%s" % (label, value),
                      "%s end amount:\n%s" % (label, value)]
        self.assertEqual(self._amounts(pages), shown)
        self.assertIn(("You receive", "0.01974 ETH\n4 of NFT ID 7\n" + NFT),
                      pages)

    def test_a_given_nft_naming_weth_warns(self):
        # The drain an amount screen hid: this wallet "gives" an ERC-721 by
        # criteria (any identifier) whose token is WETH. Seaport would move
        # the identifier the filler picks as wei of WETH, up to the whole
        # balance. The order may even pay this wallet.
        doc = copy.deepcopy(MAINNET[0])
        doc["message"]["offer"] = [
            {"itemType": 4, "token": WETH, "identifierOrCriteria": "0",
             "startAmount": "1", "endAmount": "1"}]
        pages = self._sign(doc, seaport_descriptor(described=True))
        self.assertEqual(self._amounts(pages)[:2], [
            "Give amount:\n1 NFT by criteria\n" + WETH,
            "Give end amount:\n1 NFT by criteria\n" + WETH])
        self.assertIn(
            ("WARNING", COIN_WETH + "You receive:\n0.5534078319 ETH"), pages)
        # The ERC-721 variant (50 WETH as an identifier), nothing paid back.
        doc = _paid(MAINNET[0], (0, ZERO, "1", STRANGER))
        doc["message"]["offer"] = [
            {"itemType": 2, "token": WETH,
             "identifierOrCriteria": "50000000000000000000",
             "startAmount": "1", "endAmount": "1"}]
        self.assertEqual(
            self._settlement(doc, seaport_descriptor(described=True)),
            [("WARNING", COIN_WETH + NOTHING[1])])

    def test_a_given_erc20_naming_an_nft_collection_warns(self):
        # The mirror of the drain above: this wallet "gives" an ERC-20 item
        # whose token is the listing's own NFT collection, amount = a token
        # ID. Seaport's transferFrom(from, to, 1234) moves NFT #1234. The
        # amount reads as an unknown token, and the last screen warns, even
        # with a real payment back.
        doc = _paid(MAINNET[0], (0, ZERO, "1000000000000000", SIGNER))
        doc["message"]["offer"] = [
            {"itemType": 1, "token": NFT, "identifierOrCriteria": "0",
             "startAmount": "1234", "endAmount": "1234"}]
        pages = self._sign(doc, seaport_descriptor(described=True))
        self.assertEqual(self._amounts(pages)[:2], [
            "Give amount:\n1234\nunknown token\n" + NFT,
            "Give end amount:\n1234\nunknown token\n" + NFT])
        self.assertIn(
            ("WARNING", GIVES_UNKNOWN + "You receive:\n0.001 ETH"), pages)
        # Control: the same order giving WETH, a token the table lists.
        doc["message"]["offer"][0]["token"] = WETH
        self.assertEqual(
            self._settlement(doc, seaport_descriptor(described=True)),
            [("You receive", "0.001 ETH")])

    def test_one_base_unit_of_usdc_is_dust(self):
        # A millionth of one USDC is one base unit: dust, like 1 wei.
        for amount, shown in (("1", ("WARNING", DUST + "0.000001 USDC")),
                              ("10000", ("You receive", "0.01 USDC"))):
            with self.subTest(amount=amount):
                self.assertEqual(self._settlement(_paid(
                    MAINNET[0], (1, USDC, amount, SIGNER),
                    (0, ZERO, "5589978100000000", OPENSEA_FEE))), [shown])

    def test_described_offer_items_are_given(self):
        # Offer items with a type and no recipient count as given: 1 wei
        # back warns, as with "give".
        self.assertEqual(self._settlement(
            _paid(MAINNET[0], (0, ZERO, "1", SIGNER)),
            seaport_descriptor(described=True)),
            [("WARNING", DUST + "1 Wei")])

    def test_described_offer_items_change_only_their_amounts(self):
        # Show-once with every item described: the same pages as the
        # definition without roles, but for the NFT's two amount pages (its
        # identifier, not "1 unknown token") and the added screen.
        doc = MAINNET[1]
        described = self._sign(doc, seaport_descriptor(described=True))
        without = self._sign(doc, seaport_descriptor(roles=False))
        added = ("You receive", "0.01974 ETH")
        self.assertEqual(len(described), len(without) + 1)
        changed = [(a, b) for a, b in zip(
            [p for p in described if p != added], without) if a != b]
        nft = doc["message"]["offer"][0]["token"]
        self.assertEqual([a[1] for a, _ in changed], [
            "Give amount:\nNFT ID 64\n" + nft,
            "Give end amount:\nNFT ID 64\n" + nft])
        self.assertEqual([b[1] for _, b in changed], [
            "Give amount:\n1\nunknown token\n" + nft,
            "Give end amount:\n1\nunknown token\n" + nft])

    def test_a_listing_paid_in_weth_is_calm(self):
        self.assertEqual(self._settlement(_paid(
            MAINNET[0], (1, WETH, "500000000000000000", SIGNER),
            (1, WETH, "5000000000000000", OPENSEA_FEE),
            (1, WETH, "1000000000000000", CREATOR))),
            [("You receive", "0.5 WETH")])

    def test_an_offer_for_an_nft_warns(self):
        # A collection offer: this wallet gives WETH for any NFT of a
        # collection. The device cannot value an NFT, so it says so.
        doc = _paid(MAINNET[0], (4, LISTING["message"]["offer"][0]["token"],
                                 "1", SIGNER, "1", "0"),
                    (1, WETH, "2500000000000000", OPENSEA_FEE))
        doc["message"]["offer"] = [
            {"itemType": 1, "token": WETH, "identifierOrCriteria": "0",
             "startAmount": "500000000000000000",
             "endAmount": "500000000000000000"}]
        self.assertEqual(self._settlement(doc), [(
            "WARNING", DUST + "1 NFT by criteria\n" +
            LISTING["message"]["offer"][0]["token"])])

    def test_declining_the_settlement_screen_aborts(self):
        for doc, title in ((MAINNET[1], "You receive"),
                           (_paid(MAINNET[0], (0, ZERO, "1", STRANGER)),
                            "WARNING")):
            with self.subTest(title=title):
                screens = self._sign(doc, cancel_title=title)
                assert_failure(self, self.result,
                               types.Failure_ActionCancelled,
                               "Signing cancelled by user")
                self.assertEqual(screens[-1][0], title)

    def test_without_the_opt_in_nothing_is_added(self):
        # Control: the same phishing order under the definition without
        # roles signs with no settlement screen, as 7.17 did before.
        self.assertEqual(self._settlement(
            _paid(MAINNET[0], (0, ZERO, "1", STRANGER)),
            seaport_descriptor(roles=False)), [])
