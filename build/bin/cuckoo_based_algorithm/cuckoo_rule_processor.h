#ifndef CUCKOO_RULE_PROCESSOR_H
#define CUCKOO_RULE_PROCESSOR_H

#include "cuckoo_hash_table.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
#include <map> // For StringRuleParticipation

// Information about a rule definition
struct CuckooRuleInfo {
    int sid;                            // Security ID of the rule
    std::vector<int> defined_strings_ordered; // Ordered list of string IDs for this rule
    int num_strings_in_rule;            // Total number of strings in this rule

    CuckooRuleInfo(int s, std::vector<int> strings)
        : sid(s), defined_strings_ordered(std::move(strings)), num_strings_in_rule(defined_strings_ordered.size()) {}
    CuckooRuleInfo() : sid(0), num_strings_in_rule(0) {} // Default constructor
};

// Information about a string's participation in a rule
struct CuckooParticipationInfo {
    int rule_id;                // The ID of the rule this string belongs to
    int string_index_in_rule;   // The 0-based index of this string within the rule's sequence
};

// Preprocesses and stores rule definitions for the Cuckoo-based algorithm
class CuckooRuleDatabase {
public:
    CuckooRuleDatabase() = default;

    // Adds a rule to the database.
    void add_rule(int rule_id, const std::vector<int>& string_ids_ordered, int sid);

    // Call after all rules are added to finalize any precomputation.
    // For this version, it mainly sets a flag or can be used for future optimizations.
    void finalize_preprocessing();

    // Checks if preprocessing has been finalized.
    bool is_preprocessed() const;

    // Retrieves the definition of a rule.
    // Returns std::nullopt if rule_id is not found.
    const CuckooRuleInfo* get_rule_info(int rule_id) const;

    // Retrieves the list of rules a string participates in.
    // Returns an empty vector if the string_id is not found or participates in no rules.
    const std::vector<CuckooParticipationInfo>& get_string_participation(int string_id) const;

private:
    // Stores rule definitions: rule_id -> CuckooRuleInfo
    std::unordered_map<int, CuckooRuleInfo> rule_definitions_;
    
    // Maps string_id to a list of (rule_id, index_in_rule) pairs
    // Using std::map here for ordered keys if string_ids have some locality, 
    // or std::unordered_map if not.
    std::map<int, std::vector<CuckooParticipationInfo>> string_rule_participation_;

    bool preprocessed_ = false;
    static const std::vector<CuckooParticipationInfo> empty_participation_info_; // For returning empty reference

};

// Processes packets using the Cuckoo hash-based algorithm
class CuckooPacketMatchProcessor {
public:
    // Constructor: Takes a reference to the preprocessed rule database.
    // CUCKOO_TABLE_SIZE_ESTIMATE is an estimate for how many rules might be active simultaneously.
    explicit CuckooPacketMatchProcessor(const CuckooRuleDatabase& db, size_t cuckoo_table_size_estimate = 1024);

    // Processes a packet (represented by a list of matched string IDs in order)
    // and returns a set of SIDs for fully matched rules.
    std::set<int> process_packet(const std::vector<int>& packet_matched_string_ids);

private:
    const CuckooRuleDatabase& rule_db_;
    CuckooHashTable active_rules_progress_cuckoo_table_; // Tracks progress of active rules
};

#endif // CUCKOO_RULE_PROCESSOR_H