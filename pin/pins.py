def space_used(user):
    block_sizes = {}
    for p in user.pins.all().iterator():
        block_sizes[p.multihash] = p.block_size
    return sum(block_sizes.values())
