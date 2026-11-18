"""All-chain contact proofs through real signing exchanges.

The certificate encoder and ECDSA checks are independent of firmware and
Desktop. An added name must preserve every baseline review frame and signed
byte. Public test seeds only; the owned emulator runner never finds hardware.
"""
import hashlib
import json
import os
import struct
import unittest

import common
import oled_text
from ecdsa import SECP256k1, VerifyingKey, util
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_ripple_pb2 as ripple
from keepkeylib import messages_solana_pb2 as solana
from keepkeylib import messages_ton_pb2 as ton
from keepkeylib import messages_tron_pb2 as tron
from keepkeylib import messages_nano_pb2 as nano
from keepkeylib import types_pb2 as types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path


def entry(network, address, label='Trusted recipient'):
    net, dest, name = network.encode('ascii'), address.encode('ascii'), label.encode('ascii')
    return bytes([len(net)]) + net + bytes([4, len(dest)]) + dest + bytes([len(name)]) + name


class TestNativeCertifiedContacts(common.KeepKeyTest):
    def setUp(self):
        super(TestNativeCertifiedContacts, self).setUp()
        self.requires_fullFeature()
        self.requires_release_capability('certified-contacts-all-chains')
        self.setup_mnemonic_allallall()

    def capture(self, action, reject=False):
        frames = []
        original = self.client.callback_ButtonRequest
        def button(req):
            frames.append(self.client._read_oled_after_settle())
            if reject:
                self.client.debug.press_button(False)
                return proto.ButtonAck()
            return original(req)
        self.client.callback_ButtonRequest = button
        try:
            return frames, action()
        finally:
            del self.client.callback_ButtonRequest

    def certify(self, network, address, label='Trusted recipient'):
        encoded = entry(network, address, label)
        header = b'\x01\0\0\0\x01\x01'
        root = hashlib.sha256(b'KKABLEAF' + encoded).digest()
        frames, result = self.capture(lambda: self.client.call(proto.ClearsignAttestorSign(
            payload=b'KKABREQ1' + header + encoded)))
        self.assertIsInstance(result, proto.ClearsignAttestorSignature)
        self.assertTrue(any(oled_text.shows(f, label) for f in frames))
        key = VerifyingKey.from_string(result.public_key, curve=SECP256k1)
        self.assertTrue(key.verify_digest(result.signature, hashlib.sha256(
            b'KKABRT01' + header + root).digest(), sigdecode=util.sigdecode_string))
        return b'KKABPRF1' + header + root + result.public_key + result.signature + encoded + b'\0\0'

    def load(self, proof):
        ack = self.client.call(eth.EthereumTxMetadata(signed_payload=proof))
        self.assertEqual((ack.classification, ack.display_summary), (1, 'Contact verified'))

    def exercise(self, network, address, sign):
        baseline, signed = self.capture(sign)
        proof = self.certify(network, address)
        self.load(proof)
        named, signed_named = self.capture(sign)
        self.assertEqual(signed, signed_named)
        self.assertTrue(any(oled_text.shows(f, 'Trusted recipient') for f in named))
        cursor = iter(named)
        for frame in baseline:
            self.assertTrue(any(bytes(f) == bytes(frame) for f in cursor),
                            'a mandatory baseline review frame was lost')
        # One signing attempt only. The next send must have the baseline review.
        again, result = self.capture(sign)
        self.assertEqual(signed, result)
        self.assertFalse(any(oled_text.shows(f, 'Trusted recipient') for f in again))
        # Valid proof, wrong network: raw review and exact signature preserved.
        wrong = self.certify(network + '-wrong', address)
        self.load(wrong)
        frames, result = self.capture(sign)
        self.assertEqual(signed, result)
        self.assertFalse(any(oled_text.shows(f, 'Trusted recipient') for f in frames))
        # Cancelling the name page must not produce a signature or lend its proof
        # to the next request.
        self.load(proof)
        with self.assertRaises(CallException):
            self.capture(sign, reject=True)
        frames, result = self.capture(sign)
        self.assertEqual(signed, result)
        self.assertFalse(any(oled_text.shows(f, 'Trusted recipient') for f in frames))

    def test_xrp_and_destination_tag_binding(self):
        address = 'rBKz5MC2iXdoS3XgnNSYmF69K1Yo4NS3Ws'
        msg = ripple.RippleSignTx(address_n=parse_path("m/44'/144'/0'/0/0"),
            payment=ripple.RipplePayment(amount=100000000, destination=address),
            flags=0x80000000, fee=100000, sequence=25)
        self.exercise('ripple:4109c6f2045fc7eff4cde8f9905d19c2', address, lambda: self.client.call(msg))
        proof = self.certify('ripple:4109c6f2045fc7eff4cde8f9905d19c2', address + '?dt=42')
        msg.payment.destination_tag = 43
        self.load(proof)
        frames, _ = self.capture(lambda: self.client.call(msg))
        self.assertFalse(any(oled_text.shows(f, 'Trusted recipient') for f in frames))
        msg.payment.destination_tag = 42
        self.load(proof)
        frames, _ = self.capture(lambda: self.client.call(msg))
        self.assertTrue(any(oled_text.shows(f, 'Trusted recipient') for f in frames))

    def test_solana_system_transfer(self):
        from test_msg_solana_signtx import build_system_transfer_tx
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        path = parse_path("m/44'/501'/0'/0'")
        sender = self.client.call(solana.SolanaGetAddress(address_n=path)).address
        n = 0
        for c in sender:
            n = n * 58 + alphabet.index(c)
        key = n.to_bytes(32, 'big')
        # The destination is known independently (32 bytes of zero, system key).
        msg = solana.SolanaSignTx(address_n=path,
            raw_tx=build_system_transfer_tx(key, b'\0' * 32, 1000000000))
        self.exercise('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', '1' * 32,
                      lambda: self.client.call(msg))

    def test_ton_verified_transfer_and_forged_fields(self):
        with open(os.path.join(os.path.dirname(__file__), 'ton_transfer_vectors.json')) as f:
            vectors = json.load(f)
        v = next(v for v in vectors if v['amount'] == '1000000000' and len(v['memo']) == 120 and v['workchain'] == 0 and v['bounce'])
        msg = ton.TonSignTx(address_n=parse_path("m/44'/607'/0'/0'/0'/0'"),
            raw_tx=bytes.fromhex(v['hash']), to_address=v['address'], amount=int(v['amount']),
            seqno=v['seqno'], expire_at=v['expiry'], bounce=v['bounce'], memo=v['memo'], workchain=0)
        self.exercise('ton:-239', '0:' + 'aa' * 32, lambda: self.client.call(msg))
        for field in ('amount', 'seqno', 'expire_at'):
            bad = ton.TonSignTx(); bad.CopyFrom(msg)
            setattr(bad, field, getattr(bad, field) ^ 1)
            with self.assertRaises(CallException):
                self.client.call(bad)

    def test_cosmos_send(self):
        from test_msg_cosmos_signtx import make_send
        address = 'cosmos18vhdczjut44gpsy804crfhnd5nq003nz0nf20v'
        path = parse_path("m/44'/118'/0'/0/0")
        sender = self.client.cosmos_get_address(path)
        self.exercise('cosmos:cosmoshub-4', address, lambda: self.client.cosmos_sign_tx(
            address_n=path, account_number=19637, chain_id='cosmoshub-4', fee=5000,
            gas=200000, msgs=[make_send(sender, address, 100000)], memo='audit', sequence=3))

    def test_bitcoin_output(self):
        self.client.wipe_device()
        self.setup_mnemonic_nopin_nopassphrase()
        address = '1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1'
        inp = types.TxInputType(address_n=[0], prev_hash=bytes.fromhex(
            'd5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'), prev_index=0)
        out = types.TxOutputType(address=address, amount=380000, script_type=types.PAYTOADDRESS)
        self.exercise('bip122:000000000019d6689c085ae165831e93', address,
                      lambda: self.client.sign_tx('Bitcoin', [inp], [out]))

    def test_osmosis_send(self):
        from test_msg_osmosis_signtx import make_send
        path = parse_path("m/44'/118'/0'/0/0")
        address = self.client.osmosis_get_address(path)
        self.exercise('cosmos:osmosis-1', address, lambda: self.client.osmosis_sign_tx(
            address_n=path, account_number=16359, chain_id='osmosis-1', fee=800,
            gas=290000, msgs=[make_send(address, address, 1500000)], memo='', sequence=17))

    def test_thorchain_send(self):
        from test_msg_thorchain_signtx import make_send
        path = parse_path("m/44'/931'/0'/0/0")
        address = self.client.thorchain_get_address(path)
        self.exercise('cosmos:thorchain-mainnet-v1', address, lambda: self.client.thorchain_sign_tx(
            address_n=path, account_number=92, chain_id='thorchain-mainnet-v1', fee=3000,
            gas=200000, msgs=[make_send(address, address, 10000)], memo='', sequence=3, testnet=False))

    def test_mayachain_send(self):
        from test_msg_mayachain_signtx import make_send
        path = parse_path("m/44'/931'/0'/0/0")
        address = self.client.mayachain_get_address(path)
        self.exercise('cosmos:mayachain-mainnet-v1', address, lambda: self.client.mayachain_sign_tx(
            address_n=path, account_number=92, chain_id='mayachain-mainnet-v1', fee=3000,
            gas=200000, msgs=[make_send(address, address, 10000)], memo='', sequence=3, testnet=False))

    def test_hive_transfer(self):
        from keepkeylib import hive
        from test_msg_hive import hive_path, ROLE_ACTIVE, HIVE_CHAIN_ID
        self.exercise('hive:beeab0de', 'kkrecipient', lambda: hive.sign_tx(
            self.client, address_n=hive_path(ROLE_ACTIVE), chain_id=HIVE_CHAIN_ID,
            ref_block_num=12345, ref_block_prefix=67890, expiration=1700000000,
            sender='kktester', recipient='kkrecipient', amount=1000, decimals=3,
            asset_symbol='HIVE', memo='audit'))

    def test_eos_transfer(self):
        from test_msg_eos_signtx import TestMsgEosSignTx, EOS_CHAIN_ID
        case = TestMsgEosSignTx()
        self.exercise('eos:' + EOS_CHAIN_ID[:16].hex(), 'glutton', lambda: self.client.eos_sign_tx_raw(
            proto_eos_start(case, EOS_CHAIN_ID), [case.action_transfer()]))

    def test_nano_send(self):
        from test_msg_nano_signtx import REP_OFFICIAL_1, RECIPIENT_DONATIONS
        msg = nano.NanoSignTx(address_n=parse_path("m/44'/165'/0'"), coin_name='Nano',
            parent_block=nano.NanoSignTx.ParentBlock(link=b'\x11' * 32,
                representative=REP_OFFICIAL_1, balance=(10**31).to_bytes(16, 'big')),
            link_recipient=RECIPIENT_DONATIONS, representative=REP_OFFICIAL_1,
            balance=(9 * 10**30).to_bytes(16, 'big'))
        self.exercise('nano:mainnet', RECIPIENT_DONATIONS, lambda: self.client.call(msg))

    def test_zcash_verified_user_address(self):
        import test_msg_zcash_sign_pczt_device as z
        address = z.TestZcashShieldedSigningDevice.MULTI_RECEIVER_UA
        action = z.note_action(z.CMX_ORCHARD)
        action['user_address'] = address
        self.exercise('bip122:00040fe8ec8471911baa1db1266ea15d', address,
                      lambda: self.client.zcash_sign_pczt(**z.sign_kwargs([action])))

    def test_monero_standard_subaddress_and_integrated(self):
        from test_msg_monero_sign_stream import TestMsgMoneroSignStream, CASES
        self.client.wipe_device()
        self.setup_mnemonic_abandon()
        case = TestMsgMoneroSignStream()
        case.client = self.client
        for kind in ('standard', 'subaddress', 'integrated'):
            proof = self.certify('monero:418015bb9ae982a1975da7d79277c270', CASES[kind]['recipient'])
            self.load(proof)
            # This reference signer independently checks key images, recipient
            # scanning, decrypted payment IDs and RingCT balance. Randomized
            # proofs/signatures are deliberately not compared byte-for-byte.
            _, _, _, shown = case.sign(kind)
            self.assertTrue(any(title == 'Certified contact' and 'Trustedrecipient' in body
                                for title, body in shown))
            self.assertTrue(any(title == 'Monero send' for title, _ in shown))
        # A cancellation at the first review aborts the session and consumes
        # the proof before any input secret or signing continuation is used.
        self.load(proof)
        from keepkeylib import monero_stream
        import monero_fixtures as xmr
        plan = json.loads(json.dumps(CASES['integrated']['plan']))
        with xmr.Screens(self.client, answers=(False,)):
            with self.assertRaises(CallException):
                monero_stream.sign(self.client, xmr.path(0), plan)

    def test_tron_native_send(self):
        from test_msg_tron_signtx import _field, _uint, _tron_raw
        path = parse_path("m/44'/195'/0'/0/0")
        owner = self.client.call(tron.TronGetAddress(address_n=path)).address
        address = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
        transfer = _field(1, _tron_raw(owner)) + _field(2, _tron_raw(address)) + _uint(3, 1000000)
        contract = _uint(1, 1) + _field(2, _field(1, b'type.googleapis.com/protocol.TransferContract') + _field(2, transfer))
        raw = _field(1, b'\xab\xcd') + _field(4, b'\x42' * 8) + _uint(8, 1700000000000) + _field(11, contract) + _uint(14, 1699999990000)
        msg = tron.TronSignTx(address_n=path, raw_data=raw)
        self.exercise('tron:0x2b6653dc', address, lambda: self.client.call(msg))


def proto_eos_start(case, chain):
    from keepkeylib import messages_eos_pb2 as eos
    return eos.EosSignTx(address_n=parse_path("m/44'/194'/0'/0/0"), chain_id=chain,
                         header=case.header(), num_actions=1)
