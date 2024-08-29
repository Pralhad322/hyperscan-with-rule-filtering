# bloom_filter
import hashlib

class BloomFilter:
    def __init__(self, size=12):
        self.size = size
        self.bit_array = [0] * size

    def add(self, value):
        hashes = self._hash(value)
        for hash_value in hashes:
            index = hash_value % self.size
            self.bit_array[index] = 1

    def contains(self, value):
        hashes = self._hash(value)
        for hash_value in hashes:
            index = hash_value % self.size
            if self.bit_array[index] == 0:
                return False
        return True

    def _hash(self, value):
        hash_values = []
        for i in range(4):
            hash_fn = hashlib.sha256()
            hash_fn.update(str(value).encode('utf-8'))
            hash_fn.update(str(i).encode('utf-8'))  # Add variation
            hash_value = int.from_bytes(hash_fn.digest(), byteorder='big')
            hash_values.append(hash_value)
        return hash_values
    
class BloomFilterArray:
    def __init__(self, num_filters=41):
        self.num_filters = num_filters
        self.filters = [BloomFilter() for _ in range(num_filters)]

    def add(self, rule_id, patterns):
        for pattern in patterns:
            self.filters[rule_id].add(pattern)

    def contains(self, rule_id, patterns):
        for pattern in patterns:
            if not self.filters[rule_id].contains(pattern):
                    return False
        return True
    
    def xor(self, rule_id, other_filter):
        l = self.filters[rule_id].size
        if l != other_filter.size:
            raise ValueError("Bloom filters must be of the same size")
        
        result = BloomFilter(l)
        for i in range(l):
            result.bit_array[i] = self.filters[rule_id].bit_array[i] ^ other_filter.bit_array[i]
            if result.bit_array[i]:
                return False
        return True