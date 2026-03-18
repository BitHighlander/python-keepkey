import unittest
import common

try:
    from keepkeylib import messages_mayachain_pb2 as _maya_msgs
    from keepkeylib import mapping as _mapping
    # Verify request class is registered in wire mapping (not just importable).
    # build_map() runs at import; if MayachainGetAddress is missing from
    # MessageType enum it won't be in the dispatch dict.
    _has_maya = _maya_msgs.MayachainGetAddress in _mapping.map_class_to_type
except Exception:
    _has_maya = False

import keepkeylib.messages_pb2 as proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import parse_path

DEFAULT_BIP32_PATH = "m/44h/931h/0h/0/0"

@unittest.skipUnless(_has_maya, "MayaChain message mapping not registered in this build")
class TestMsgMayaChainGetAddress(common.KeepKeyTest):

    def test_mayachain_get_address(self):
        self.requires_firmware("7.9.1")
        self.requires_fullFeature()
        self.setup_mnemonic_nopin_nopassphrase()
        address = self.client.mayachain_get_address(parse_path(DEFAULT_BIP32_PATH), testnet=True)
        self.assertEqual(address, "smaya1ls33ayg26kmltw7jjy55p32ghjna09zp2mf0av")

if __name__ == '__main__':
    unittest.main()
