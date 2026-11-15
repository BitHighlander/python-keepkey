"""Monero wire schema (device-protocol messages-monero.proto).

The binding tests need no device. The device test checks that firmware which
does not report monero-signing refuses every Monero request cleanly.
"""

import unittest

import common
from keepkeylib import mapping
from keepkeylib import messages_monero_pb2 as monero_proto
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as proto_types

MONERO_WIRE_IDS = {
    1800: 'MoneroGetAddress',
    1801: 'MoneroAddress',
    1802: 'MoneroGetWatchKey',
    1803: 'MoneroWatchKey',
    1804: 'MoneroKeyImageExportInitRequest',
    1805: 'MoneroKeyImageExportInitAck',
    1806: 'MoneroKeyImageSyncStepRequest',
    1807: 'MoneroKeyImageSyncStepAck',
    1808: 'MoneroKeyImageSyncFinalRequest',
    1809: 'MoneroKeyImageSyncFinalAck',
    1810: 'MoneroTxInitRequest',
    1811: 'MoneroTxInitAck',
    1812: 'MoneroTxSetInputRequest',
    1813: 'MoneroTxSetInputAck',
    1814: 'MoneroTxInputViniRequest',
    1815: 'MoneroTxInputViniAck',
    1816: 'MoneroTxAllInputsSetRequest',
    1817: 'MoneroTxAllInputsSetAck',
    1818: 'MoneroTxSetOutputRequest',
    1819: 'MoneroTxSetOutputAck',
    1820: 'MoneroTxAllOutSetRequest',
    1821: 'MoneroTxAllOutSetAck',
    1822: 'MoneroTxSignInputRequest',
    1823: 'MoneroTxSignInputAck',
    1824: 'MoneroTxFinalRequest',
    1825: 'MoneroTxFinalAck',
}


class TestMoneroProtocolBindings(unittest.TestCase):

    def test_wire_ids_map_to_monero_messages(self):
        for wire_id, name in MONERO_WIRE_IDS.items():
            self.assertEqual(proto.MessageType.Value('MessageType_' + name), wire_id)
            self.assertIs(mapping.get_class(wire_id), getattr(monero_proto, name))

    def test_reserved_block_is_unallocated(self):
        allocated = set(proto.MessageType.values())
        for wire_id in range(1826, 1850):
            self.assertNotIn(wire_id, allocated)

    def test_capability_value_is_31(self):
        self.assertEqual(
            proto.Features.Capability.Value('CAPABILITY_MONERO_SIGNING'), 31)

    def test_no_secret_offload_fields(self):
        # Unlike Trezor's protocol, the host never carries an encrypted spend
        # key or CLSAG alpha between steps.
        for message in (monero_proto.MoneroTxSetInputAck,
                        monero_proto.MoneroTxSignInputRequest):
            fields = message.DESCRIPTOR.fields_by_name
            self.assertNotIn('spend_key', fields)
            self.assertNotIn('pseudo_out_alpha', fields)


class TestMoneroWithoutSigner(common.KeepKeyTest):

    def test_requests_are_refused_without_the_capability(self):
        reported = self.firmware_capabilities()
        if reported is not None and 'monero-signing' in reported:
            self.skipTest('Firmware implements Monero signing')
        self.setup_mnemonic_nopin_nopassphrase()
        for wire_id, name in sorted(MONERO_WIRE_IDS.items()):
            if not name.startswith('MoneroGet') and not name.endswith('Request'):
                continue  # responses are never sent to the device
            with self.subTest(name):
                response = self.client.call_raw(getattr(monero_proto, name)())
                self.assertIsInstance(response, proto.Failure)
                self.assertEqual(response.code, proto_types.Failure_UnexpectedMessage)


if __name__ == '__main__':
    unittest.main()
