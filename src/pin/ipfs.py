import random


class MockIPFS:

    def __init__(address, port=5001):
        pass

    def get_cumulative_size(self, multihash):
        return random.randint(128, 128*128)

    def pin(self, multihash):
        pass
