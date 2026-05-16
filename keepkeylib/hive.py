from . import messages_hive_pb2 as proto


def get_public_key(client, address_n, show_display=False):
    return client.call(
        proto.HiveGetPublicKey(address_n=address_n, show_display=show_display)
    )


def sign_tx(client, address_n, chain_id, ref_block_num, ref_block_prefix,
            expiration, sender, recipient, amount, decimals, asset_symbol, memo=''):
    # 'from' is a Python keyword so use **-unpacking to set the field
    return client.call(proto.HiveSignTx(**{
        'address_n': address_n,
        'chain_id': chain_id,
        'ref_block_num': ref_block_num,
        'ref_block_prefix': ref_block_prefix,
        'expiration': expiration,
        'from': sender,
        'to': recipient,
        'amount': amount,
        'decimals': decimals,
        'asset_symbol': asset_symbol,
        'memo': memo,
    }))
