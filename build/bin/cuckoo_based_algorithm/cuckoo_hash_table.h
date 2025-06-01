#ifndef CUCKOO_HASH_TABLE_H
#define CUCKOO_HASH_TABLE_H

#include <vector>
#include <functional> // For std::hash
#include <optional>   // For std::optional
#include <string>     // For std::string in exceptions (though not directly used here)

// A simple entry in the Cuckoo hash table
struct CuckooEntry {
    int key;
    int value;
    bool occupied;

    CuckooEntry() : key(0), value(0), occupied(false) {}
    CuckooEntry(int k, int v) : key(k), value(v), occupied(true) {}
};

class CuckooHashTable {
public:
    // Constructor: size is the total desired capacity, will be split between two tables.
    explicit CuckooHashTable(size_t total_capacity);

    // Inserts or updates a key-value pair.
    // Returns true on success, false if insertion fails (e.g., cycle or too many displacements).
    bool insert_or_update(int key, int value);

    // Looks up a key and returns its value.
    // Returns std::nullopt if the key is not found.
    std::optional<int> lookup(int key) const;

    // Removes a key. Returns true if key was found and removed, false otherwise.
    bool remove(int key);

    // Clears the hash table, marking all entries as not occupied.
    void clear();

    // For debugging: prints the contents of the tables (optional)
    // void print_table() const;

private:
    std::vector<CuckooEntry> table1;
    std::vector<CuckooEntry> table2;
    size_t single_table_size; // Size of each individual table
    size_t num_elements;

    // Hash functions
    size_t hash1(int key) const;
    size_t hash2(int key) const;

    // Max displacement attempts before giving up on an insertion.
    // This helps prevent infinite loops in case of cycles if not handled by rehash.
    const int MAX_DISPLACEMENTS = 100; 
};

#endif // CUCKOO_HASH_TABLE_H
