"""
Canonical binary serializer for KeepKey EVM signed metadata.

Produces the exact binary format that firmware's parse_metadata_binary() expects.
Used for generating test vectors and by the Pioneer signing service.

Binary format:
  version(1) + chain_id(4 BE) + contract_address(20) + selector(4) +
  tx_hash(32) + method_name_len(2 BE) + method_name(var) + num_args(1) +
  [per arg: name_len(1) + name(var) + format(1) + value_len(2 BE) + value(var)] +
  classification(1) + timestamp(4 BE) + key_id(1) + signature(64) + recovery(1)
"""

import struct
import hashlib
import time

# Keep in sync with firmware signed_metadata.h
ARG_FORMAT_RAW = 0
ARG_FORMAT_ADDRESS = 1
ARG_FORMAT_AMOUNT = 2
ARG_FORMAT_BYTES = 3

CLASSIFICATION_OPAQUE = 0
CLASSIFICATION_VERIFIED = 1
CLASSIFICATION_MALFORMED = 2

# Test key: private key = 0x01 (secp256k1 generator point G)
# Only for testing — production uses HSM-protected key.
TEST_PRIVATE_KEY = b'\x00' * 31 + b'\x01'


def serialize_metadata(
    chain_id: int,
    contract_address: bytes,
    selector: bytes,
    tx_hash: bytes,
    method_name: str,
    args: list,
    classification: int = CLASSIFICATION_VERIFIED,
    timestamp: int = None,
    key_id: int = 0,
    version: int = 1,
) -> bytes:
    """Serialize metadata fields into canonical binary (unsigned).

    Args:
        chain_id: EIP-155 chain ID
        contract_address: 20-byte contract address
        selector: 4-byte function selector
        tx_hash: 32-byte keccak-256 of unsigned tx (can be zeroed for phase 1)
        method_name: UTF-8 method name (max 64 bytes)
        args: list of dicts with keys: name, format, value (bytes)
        classification: 0=OPAQUE, 1=VERIFIED, 2=MALFORMED
        timestamp: Unix seconds (defaults to now)
        key_id: embedded public key slot (0-3)
        version: schema version (must be 1)

    Returns:
        Canonical binary payload (without signature — call sign_metadata next)
    """
    if timestamp is None:
        timestamp = int(time.time())

    assert len(contract_address) == 20
    assert len(selector) == 4
    assert len(tx_hash) == 32
    assert len(method_name.encode('utf-8')) <= 64
    assert len(args) <= 8

    buf = bytearray()

    # version
    buf.append(version)

    # chain_id (4 bytes BE)
    buf.extend(struct.pack('>I', chain_id))

    # contract_address (20 bytes)
    buf.extend(contract_address)

    # selector (4 bytes)
    buf.extend(selector)

    # tx_hash (32 bytes)
    buf.extend(tx_hash)

    # method_name (2-byte length prefix + UTF-8)
    name_bytes = method_name.encode('utf-8')
    buf.extend(struct.pack('>H', len(name_bytes)))
    buf.extend(name_bytes)

    # num_args
    buf.append(len(args))

    # args
    for arg in args:
        # name (1-byte length prefix + UTF-8)
        arg_name = arg['name'].encode('utf-8')
        assert len(arg_name) <= 32
        buf.append(len(arg_name))
        buf.extend(arg_name)

        # format
        buf.append(arg['format'])

        # value (2-byte length prefix + raw bytes)
        val = arg['value']
        assert len(val) <= 32  # METADATA_MAX_ARG_VALUE_LEN
        buf.extend(struct.pack('>H', len(val)))
        buf.extend(val)

    # classification
    buf.append(classification)

    # timestamp (4 bytes BE)
    buf.extend(struct.pack('>I', timestamp))

    # key_id
    buf.append(key_id)

    return bytes(buf)


def sign_metadata(payload: bytes, private_key: bytes = None) -> bytes:
    """Sign the canonical binary payload and return the complete signed blob.

    Signs SHA-256(payload) with secp256k1 ECDSA, appends signature(64) + recovery(1).

    Args:
        payload: canonical binary from serialize_metadata()
        private_key: 32-byte secp256k1 private key (defaults to test key)

    Returns:
        Complete signed blob: payload + signature(64) + recovery(1)
    """
    if private_key is None:
        private_key = TEST_PRIVATE_KEY

    digest = hashlib.sha256(payload).digest()

    try:
        from ecdsa import SigningKey, SECP256k1, util
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        sig_der = sk.sign_digest(digest, sigencode=util.sigencode_string)
        # sig_der is r(32) || s(32) = 64 bytes
        r = sig_der[:32]
        s = sig_der[32:]

        # Recovery: compute v (27 or 28)
        vk = sk.get_verifying_key()
        pubkey = b'\x04' + vk.to_string()
        # Try recovery with v=0 and v=1
        from ecdsa import VerifyingKey
        for v in (0, 1):
            try:
                recovered = VerifyingKey.from_public_key_recovery_with_digest(
                    sig_der, digest, SECP256k1, hashfunc=hashlib.sha256
                )
                for i, rk in enumerate(recovered):
                    if rk.to_string() == vk.to_string():
                        recovery = 27 + i
                        break
                else:
                    recovery = 27
                break
            except Exception:
                continue
        else:
            recovery = 27

    except ImportError:
        # Fallback: zero signature for struct-only testing
        r = b'\x00' * 32
        s = b'\x00' * 32
        recovery = 27

    return payload + r + s + bytes([recovery])


def build_test_metadata(
    chain_id=1,
    contract_address=None,
    selector=None,
    tx_hash=None,
    method_name='supply',
    args=None,
    **kwargs,
) -> bytes:
    """Convenience: build a complete signed test metadata blob.

    Defaults to an Aave V3 supply() call on Ethereum mainnet.
    """
    if contract_address is None:
        contract_address = bytes.fromhex('7d2768de32b0b80b7a3454c06bdac94a69ddc7a9')
    if selector is None:
        selector = bytes.fromhex('617ba037')
    if tx_hash is None:
        tx_hash = b'\x00' * 32
    if args is None:
        args = [
            {
                'name': 'asset',
                'format': ARG_FORMAT_ADDRESS,
                'value': bytes.fromhex('6b175474e89094c44da98b954eedeac495271d0f'),
            },
            {
                'name': 'amount',
                'format': ARG_FORMAT_AMOUNT,
                'value': (10500000000000000000).to_bytes(32, 'big'),
            },
            {
                'name': 'onBehalfOf',
                'format': ARG_FORMAT_ADDRESS,
                'value': bytes.fromhex('d8da6bf26964af9d7eed9e03e53415d37aa96045'),
            },
        ]

    payload = serialize_metadata(
        chain_id=chain_id,
        contract_address=contract_address,
        selector=selector,
        tx_hash=tx_hash,
        method_name=method_name,
        args=args,
        **kwargs,
    )
    return sign_metadata(payload)
