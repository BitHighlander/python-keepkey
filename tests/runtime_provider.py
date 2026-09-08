"""Explicit consent fixture for firmware with RAM-only provider identities."""
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from keepkeylib import mapping, messages_pb2 as proto

LOAD_CLEARSIGN_SIGNER_WIRE_ID = 117
FIELD = descriptor_pb2.FieldDescriptorProto

# The audited host pin predates this message. Keep the fixture wire contract
# narrow rather than importing unrelated generated protocol changes.
spec = descriptor_pb2.FileDescriptorProto(name="runtime_provider_fixture.proto", syntax="proto2")
message = spec.message_type.add(name="FixtureLoadClearsignSigner")
for number, name, kind in [(1, "key_id", FIELD.TYPE_UINT32),
                           (2, "pubkey", FIELD.TYPE_BYTES),
                           (3, "alias", FIELD.TYPE_STRING),
                           (7, "persist", FIELD.TYPE_BOOL)]:
    message.field.add(name=name, number=number, type=kind, label=FIELD.LABEL_OPTIONAL)
pool = descriptor_pool.DescriptorPool()
pool.Add(spec)
LoadSigner = message_factory.MessageFactory(pool).GetPrototype(
    pool.FindMessageTypeByName("FixtureLoadClearsignSigner"))
if (LOAD_CLEARSIGN_SIGNER_WIRE_ID in mapping.map_type_to_class or
        LOAD_CLEARSIGN_SIGNER_WIRE_ID in mapping.map_class_to_type.values()):
    raise RuntimeError("Runtime provider fixture wire ID is already registered")
mapping.map_class_to_type[LoadSigner] = LOAD_CLEARSIGN_SIGNER_WIRE_ID
mapping.map_type_to_class[LOAD_CLEARSIGN_SIGNER_WIRE_ID] = LoadSigner


def load_test_provider(client):
    from ecdsa import SigningKey, SECP256k1
    from keepkeylib.signed_metadata import TEST_PRIVATE_KEY
    key = SigningKey.from_string(TEST_PRIVATE_KEY, curve=SECP256k1)
    public_key = key.get_verifying_key().to_string()
    compressed_key = bytes([2 | (public_key[-1] & 1)]) + public_key[:32]
    request = LoadSigner(
        key_id=3, alias="Integration provider", persist=False,
        pubkey=compressed_key)
    with client:
        client.set_expected_responses([proto.ButtonRequest(), proto.Success()])
        client.call(request)
