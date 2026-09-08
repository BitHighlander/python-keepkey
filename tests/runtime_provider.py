"""Explicit consent fixture for firmware with RAM-only provider identities."""
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from keepkeylib import mapping, messages_pb2 as proto

# The audited host pin predates this message. Keep the fixture wire contract
# narrow rather than importing unrelated generated protocol changes.
spec = descriptor_pb2.FileDescriptorProto(name="runtime_provider_fixture.proto", syntax="proto2")
message = spec.message_type.add(name="FixtureLoadClearsignSigner")
for number, name, kind in [(1, "key_id", 13), (2, "pubkey", 12),
                           (3, "alias", 9), (7, "persist", 8)]:
    message.field.add(name=name, number=number, type=kind, label=1)
pool = descriptor_pool.DescriptorPool()
pool.Add(spec)
LoadSigner = message_factory.MessageFactory(pool).GetPrototype(
    pool.FindMessageTypeByName("FixtureLoadClearsignSigner"))
mapping.map_class_to_type[LoadSigner] = 117
mapping.map_type_to_class[117] = LoadSigner


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
