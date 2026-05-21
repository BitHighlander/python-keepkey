# This file is part of the keepkey project.
#
# Copyright (C) 2022 markrypto
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import unittest
import common
import binascii
import json

import keepkeylib.messages_pb2 as proto
import keepkeylib.messages_ethereum_pb2 as eth_proto
import keepkeylib.types_pb2 as proto_types
from keepkeylib.client import CallException
from keepkeylib.tools import int_to_big_endian
from keepkeylib import tools

class TestMsgEthereumSignTypedDataHash(common.KeepKeyTest):
  
    def test_ethereum_sign_typed_data_hash(self):
        self.requires_fullFeature()
        self.requires_firmware("7.4.0")
        self.setup_mnemonic_allallall()
        f = open('sign_typed_data.json')
        txtests = json.load(f)
        f.close()

        for test in txtests['tests']:
            print("test: ", json.dumps(test['name']))
            if test['parameters']['message_hash'] != None:
                retval = self.client.ethereum_sign_typed_data_hash(
                    n = tools.parse_path(test['parameters']['path']),
                    ds_hash = binascii.unhexlify(test['parameters']['domain_separator_hash'][2:]),
                    m_hash = binascii.unhexlify(test['parameters']['message_hash'][2:])
                    )
            else:
                retval = self.client.ethereum_sign_typed_data_hash(
                    n = tools.parse_path(test['parameters']['path']),
                    ds_hash = binascii.unhexlify(test['parameters']['domain_separator_hash'][2:]),
                    )

            self.assertEqual(retval.address, test['result']['address'])
            self.assertEqual(binascii.hexlify(retval.signature), test['result']['sig'][2:])

class TestEIP712Security(common.KeepKeyTest):
    """Regression tests for fix/eip712-security.

    The firmware previously accepted negative values for uint256 fields in
    EIP-712 typed data (sign_typed_data_hash path), which could allow a
    crafted message to produce a misleading or exploitable signature.
    """

    def test_eip712_normal_hash_signing_still_works(self):
        """Normal EIP-712 domain + message hash signing must still succeed after the security fix."""
        self.requires_fullFeature()
        self.requires_firmware("7.4.0")
        self.setup_mnemonic_allallall()

        # Values taken from EIP-712 test suite — simple transfer permit domain
        domain_separator_hash = binascii.unhexlify(
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        )
        message_hash = binascii.unhexlify(
            "2d7a851c2b6942cbca9ca80b9b4e7ac6e00d0f17b3e8e3d0b2faa5a15f17de6"
        )

        retval = self.client.ethereum_sign_typed_data_hash(
            n=tools.parse_path("m/44'/60'/0'/0/0"),
            ds_hash=domain_separator_hash,
            m_hash=message_hash,
        )

        self.assertIsNotNone(retval.signature)
        self.assertEqual(len(retval.signature), 65)

    def test_eip712_hash_signing_no_message_hash(self):
        """EIP-712 domain-only (no message hash) signing must still succeed."""
        self.requires_fullFeature()
        self.requires_firmware("7.4.0")
        self.setup_mnemonic_allallall()

        domain_separator_hash = binascii.unhexlify(
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        )

        retval = self.client.ethereum_sign_typed_data_hash(
            n=tools.parse_path("m/44'/60'/0'/0/0"),
            ds_hash=domain_separator_hash,
        )

        self.assertIsNotNone(retval.signature)
        self.assertEqual(len(retval.signature), 65)


if __name__ == '__main__':
    unittest.main()
