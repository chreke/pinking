def space_used(user):
    block_sizes = {}
    for p in user.pins.filter(count__gt=0).iterator():
        block_sizes[p.multihash] = p.block_size
    return sum(block_sizes.values())
