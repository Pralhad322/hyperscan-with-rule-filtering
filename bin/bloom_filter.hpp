#ifndef BLOOM_FILTER_HPP
#define BLOOM_FILTER_HPP

#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <stdexcept>

class BloomFilter {
public:
    BloomFilter(size_t size = 12) : size(size), bitArray(size, 0) {}

    void add(int value) {
        auto hashes = _hash(value);
        for (auto hash : hashes) {
            size_t index = hash % size;
            bitArray[index] = 1;
        }
    }

    bool contains(int value) const {
        auto hashes = _hash(value);
        for (auto hash : hashes) {
            size_t index = hash % size;
            if (bitArray[index] == 0) return false;
        }
        return true;
    }

    size_t getSize() const {
        return size;
    }

// private:
    size_t size;
    std::vector<uint8_t> bitArray;

    std::vector<uint64_t> _hash(int value) const {
        std::vector<uint64_t> hashValues;
        std::hash<std::string> hashFn;
        for (size_t i = 0; i < 4; ++i) {
            std::string input = std::to_string(value) + std::to_string(i);
            size_t hashValue = hashFn(input);
            hashValues.push_back(hashValue);
        }
        return hashValues;
    }
};

class BloomFilterArray {
public:
    BloomFilterArray(size_t numFilters = 41) : numFilters(numFilters), filters(numFilters) {}

    void add(int ruleId, const std::vector<int>& patterns) {
        for (int pattern : patterns) {
            filters[ruleId].add(pattern);
        }
    }

    bool contains(int ruleId, const std::vector<int>& patterns) const {
        for (int pattern : patterns) {
            if (!filters[ruleId].contains(pattern)) {
                return false;
            }
        }
        return true;
    }

    bool xorOperation(int ruleId, const BloomFilter& otherFilter) const {
        if (filters[ruleId].getSize() != otherFilter.getSize()) {
            throw std::invalid_argument("Bloom filters must be of the same size");
        }

        BloomFilter result(filters[ruleId].getSize());
        for (size_t i = 0; i < filters[ruleId].getSize(); ++i) {
            uint8_t bit = filters[ruleId].bitArray[i] ^ otherFilter.bitArray[i];
            result.bitArray[i] = bit;
        }
        return result.contains(1);  
    }

// private:
    size_t numFilters;
    std::vector<BloomFilter> filters;
};

#endif // BLOOM_FILTER_HPP
