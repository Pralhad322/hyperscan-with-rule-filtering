#include "cuckoo_hash_table.h"
#include <stdexcept> // For std::runtime_error (though not used in this simplified version)
#include <iostream>  // For debugging (optional)

// Constructor
CuckooHashTable::CuckooHashTable(size_t total_capacity) : num_elements(0) {
    if (total_capacity == 0) total_capacity = 2; // Minimum size to avoid division by zero
    single_table_size = (total_capacity + 1) / 2; // Ensure each table gets roughly half
    table1.resize(single_table_size);
    table2.resize(single_table_size);
}

// Hash function 1
size_t CuckooHashTable::hash1(int key) const {
    // Simple modulo hash, can be replaced with something more robust
    return std::hash<int>{}(key) % single_table_size;
}

// Hash function 2
size_t CuckooHashTable::hash2(int key) const {
    // Another simple hash, ensure it's different from hash1 for most keys
    // For example, a common technique is to XOR with a constant or use a different prime
    return (std::hash<int>{}(key) / single_table_size) % single_table_size; 
}

// Insert or update a key-value pair
bool CuckooHashTable::insert_or_update(int key, int value) {
    // Check if key already exists in table1
    size_t pos1 = hash1(key);
    if (table1[pos1].occupied && table1[pos1].key == key) {
        table1[pos1].value = value; // Update existing key
        return true;
    }

    // Check if key already exists in table2
    size_t pos2 = hash2(key);
    if (table2[pos2].occupied && table2[pos2].key == key) {
        table2[pos2].value = value; // Update existing key
        return true;
    }

    // If key does not exist, proceed with insertion logic
    // Simplified insertion: try to place in table1 first, then displace if needed.
    // A full Cuckoo insertion involves a loop of displacements and potentially a rehash.
    // This is a very basic version without rehash for simplicity.

    int current_key = key;
    int current_value = value;

    for (int i = 0; i < MAX_DISPLACEMENTS; ++i) {
        // Try to insert into table1
        pos1 = hash1(current_key);
        if (!table1[pos1].occupied) {
            table1[pos1] = CuckooEntry(current_key, current_value);
            num_elements++;
            return true;
        }

        // Displace from table1
        CuckooEntry displaced_entry1 = table1[pos1];
        table1[pos1] = CuckooEntry(current_key, current_value);
        current_key = displaced_entry1.key;
        current_value = displaced_entry1.value;

        // Try to insert into table2
        pos2 = hash2(current_key);
        if (!table2[pos2].occupied) {
            table2[pos2] = CuckooEntry(current_key, current_value);
            num_elements++;
            return true;
        }

        // Displace from table2
        CuckooEntry displaced_entry2 = table2[pos2];
        table2[pos2] = CuckooEntry(current_key, current_value);
        current_key = displaced_entry2.key;
        current_value = displaced_entry2.value;
    }
    
    // If we reach here, insertion failed after MAX_DISPLACEMENTS
    // In a full implementation, this would trigger a rehash.
    // std::cerr << "Cuckoo insertion failed for key: " << key << std::endl;
    return false; 
}

// Look up a key
std::optional<int> CuckooHashTable::lookup(int key) const {
    size_t pos1 = hash1(key);
    if (table1[pos1].occupied && table1[pos1].key == key) {
        return table1[pos1].value;
    }

    size_t pos2 = hash2(key);
    if (table2[pos2].occupied && table2[pos2].key == key) {
        return table2[pos2].value;
    }
    return std::nullopt; // Key not found
}

// Remove a key
bool CuckooHashTable::remove(int key) {
    size_t pos1 = hash1(key);
    if (table1[pos1].occupied && table1[pos1].key == key) {
        table1[pos1].occupied = false;
        num_elements--;
        return true;
    }

    size_t pos2 = hash2(key);
    if (table2[pos2].occupied && table2[pos2].key == key) {
        table2[pos2].occupied = false;
        num_elements--;
        return true;
    }
    return false; // Key not found
}

// Clear the hash table
void CuckooHashTable::clear() {
    for (size_t i = 0; i < single_table_size; ++i) {
        table1[i].occupied = false;
        table2[i].occupied = false;
    }
    num_elements = 0;
}

/*
// Optional: For debugging
void CuckooHashTable::print_table() const {
    std::cout << "Table 1:" << std::endl;
    for (size_t i = 0; i < single_table_size; ++i) {
        if (table1[i].occupied) {
            std::cout << "  [" << i << "]: (" << table1[i].key << ", " << table1[i].value << ")" << std::endl;
        }
    }
    std::cout << "Table 2:" << std::endl;
    for (size_t i = 0; i < single_table_size; ++i) {
        if (table2[i].occupied) {
            std::cout << "  [" << i << "]: (" << table2[i].key << ", " << table2[i].value << ")" << std::endl;
        }
    }
}
*/