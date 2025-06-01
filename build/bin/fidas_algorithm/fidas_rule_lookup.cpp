#include "fidas_rule_lookup.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cmath>
#include <set>

// --- FidasRuleDatabase Implementation ---

FidasRuleDatabase::FidasRuleDatabase() : preprocessed_(false) {}

void FidasRuleDatabase::add_rule(int rule_id, int sid, const std::vector<int>& required_strings, int min_matches) {
    if (rules_.find(rule_id) != rules_.end()) {
        std::cerr << "Warning: Rule ID " << rule_id << " already exists, overwriting." << std::endl;
    }
    
    rules_[rule_id] = FidasRule(rule_id, sid, required_strings, min_matches);
    preprocessed_ = false; // Need to reprocess after adding rules
}

// void FidasRuleDatabase::finalize_preprocessing() {
//     string_to_rules_.clear();
    
//     // Initialize R2-table and R1-table
//     std::cout << "initalizing R2-table and R1-table..." << std::endl;
//     for (int i = 0; i < R2_TABLE_SIZE; i++) {
//         r2_table_[i] = R2TableEntry();  // Initialize as empty
//     }
//     for (int i = 0; i < R1_TABLE_SIZE; i++) {
//         r1_table_[i] = R1TableEntry();  // Initialize as empty
//     }
    
//     // Build the legacy string-to-rules mapping for compatibility
//     std::cout << "Building string-to-rules mapping..." << std::endl;
//     for (const auto& rule_pair : rules_) {
//         int rule_id = rule_pair.first;
//         const FidasRule& rule = rule_pair.second;
        
//         for (int string_id : rule.required_string_ids) {
//             string_to_rules_[string_id].push_back(rule_id);
//         }
//     }
    
//     // Build R1-table: rule_id -> required sub-rule IDs
//     std::cout << "Building R1-table..." << std::endl;
//     for (const auto& rule_pair : rules_) {
//         int rule_id = rule_pair.first;
//         const FidasRule& rule = rule_pair.second;
        
//         if (rule_id >= 0 && rule_id < R1_TABLE_SIZE) {
//             R1TableEntry& r1_entry = r1_table_[rule_id];
//             for (int sub_rule_id : rule.required_string_ids) {
//                 r1_entry.add_sub_rule(sub_rule_id);
//             }
//         }
//     }
    
//     // Build R2-table: sub-rule ID -> rule ID(s)
//     // This implements the optimized mapping described in the FIDAS paper
//     std::unordered_map<int, std::vector<int>> sub_rule_to_rules;
    
//     // First pass: collect all sub-rule -> rule mappings
//     std::cout << "Collecting sub-rule to rule mappings..." << std::endl;    
//     for (const auto& rule_pair : rules_) {
//         int rule_id = rule_pair.first;
//         const FidasRule& rule = rule_pair.second;
        
//         for (int sub_rule_id : rule.required_string_ids) {
//             sub_rule_to_rules[sub_rule_id].push_back(rule_id);
//         }
//     }
    
//     // Second pass: populate R2-table with optimized mappings
//     std::cout << "Populating R2-table with optimized mappings..." << std::endl;
    
//     for (const auto& mapping : sub_rule_to_rules) {
//         int sub_rule_id = mapping.first;
//         const std::vector<int>& rule_ids = mapping.second;
        
//         int hash_index = hash_sub_rule_id(sub_rule_id);
//         R2TableEntry& r2_entry = r2_table_[hash_index];
        
//         // Handle hash collisions with linear probing
//         while (!r2_entry.is_empty()) {
//             hash_index = (hash_index + 1) % R2_TABLE_SIZE;
//             r2_entry = r2_table_[hash_index];
//         }
        
//         if (rule_ids.size() == 1) {
//             // Optimized case: one sub-rule maps to one rule
//             r2_entry.set_single_rule(rule_ids[0]);
//         } else {
//             // Multiple rules case: use linked list
//             r2_entry.set_multiple_rules(rule_ids);
//         }
//     }
    
//     preprocessed_ = true;
    
//     std::cout << "FIDAS Rule Database preprocessed: " 
//               << rules_.size() << " rules, " 
//               << string_to_rules_.size() << " unique strings" << std::endl;
//     std::cout << "R2-table and R1-table built according to FIDAS algorithm" << std::endl;
// }

void FidasRuleDatabase::finalize_preprocessing() {
    string_to_rules_.clear();
    
    // Initialize R2-table and R1-table
    std::cout << "Initializing R2-table and R1-table..." << std::endl;
    for (int i = 0; i < R2_TABLE_SIZE; i++) {
        r2_table_[i] = R2TableEntry();  // Initialize as empty
    }
    for (int i = 0; i < R1_TABLE_SIZE; i++) {
        r1_table_[i] = R1TableEntry();  // Initialize as empty
    }
    
    // Build the legacy string-to-rules mapping for compatibility
    std::cout << "Building string-to-rules mapping..." << std::endl;
    for (const auto& rule_pair : rules_) {
        int rule_id = rule_pair.first;
        const FidasRule& rule = rule_pair.second;
        
        for (int string_id : rule.required_string_ids) {
            string_to_rules_[string_id].push_back(rule_id);
        }
    }
    
    // Build R1-table: rule_id -> required sub-rule IDs
    std::cout << "Building R1-table..." << std::endl;
    for (const auto& rule_pair : rules_) {
        int rule_id = rule_pair.first;
        const FidasRule& rule = rule_pair.second;
        
        if (rule_id >= 0 && rule_id < R1_TABLE_SIZE) {
            R1TableEntry& r1_entry = r1_table_[rule_id];
            for (int sub_rule_id : rule.required_string_ids) {
                r1_entry.add_sub_rule(sub_rule_id);
            }
        }
    }
    
    // ========== OPTIMIZED R2-TABLE MAPPING (FIDAS PAPER ALGORITHM) ==========
    
    // Build R2-table: sub-rule ID -> rule ID(s) with optimization
    std::unordered_map<int, std::vector<int>> sub_rule_to_rules;
    
    // First pass: collect all sub-rule -> rule mappings
    std::cout << "Collecting sub-rule to rule mappings for optimization..." << std::endl;    
    for (const auto& rule_pair : rules_) {
        int rule_id = rule_pair.first;
        const FidasRule& rule = rule_pair.second;
        
        for (int sub_rule_id : rule.required_string_ids) {
            sub_rule_to_rules[sub_rule_id].push_back(rule_id);
        }
    }
    
    // Create sorted list of sub-rules by rule count (ascending - unique sub-rules first)
    std::cout << "Sorting sub-rules by rule count for optimal processing..." << std::endl;
    std::vector<std::pair<int, int>> sub_rule_rule_count; // (sub_rule_id, rule_count)
    for (const auto& mapping : sub_rule_to_rules) {
        int sub_rule_id = mapping.first;
        int rule_count = mapping.second.size();
        sub_rule_rule_count.emplace_back(sub_rule_id, rule_count);
    }
    
    // Sort by rule count (ascending - unique sub-rules processed first)
    std::sort(sub_rule_rule_count.begin(), sub_rule_rule_count.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second; // Ascending by rule count
              });
    
    // Track assigned rules to implement FIDAS optimization
    std::unordered_set<int> assigned_rules;
    int unique_mappings = 0;
    int null_mappings = 0;
    int linked_list_mappings = 0;
    
    // Optimized R2-table population
    std::cout << "Populating R2-table with FIDAS optimized mappings..." << std::endl;
    
    for (const auto& sub_rule_pair : sub_rule_rule_count) {
        int sub_rule_id = sub_rule_pair.first;
        const std::vector<int>& rule_ids = sub_rule_to_rules[sub_rule_id];
        
        // Filter out already assigned rules
        std::vector<int> remaining_rules;
        for (int rule_id : rule_ids) {
            if (assigned_rules.find(rule_id) == assigned_rules.end()) {
                remaining_rules.push_back(rule_id);
            }
        }
        
        int hash_index = hash_sub_rule_id(sub_rule_id);
        R2TableEntry& r2_entry = r2_table_[hash_index];
        
        // Handle hash collisions with linear probing
        while (!r2_entry.is_empty()) {
            hash_index = (hash_index + 1) % R2_TABLE_SIZE;
            r2_entry = r2_table_[hash_index];
        }
        
        if (remaining_rules.empty()) {
            // All rules already assigned → map to null (optimization)
            r2_entry.set_empty();  // Mark as empty/null
            null_mappings++;
            // std::cout << "Sub-rule " << sub_rule_id << " mapped to null (all rules assigned)" << std::endl;
            
        } else if (remaining_rules.size() == 1) {
            // Exactly one unassigned rule → unique mapping (optimal case)
            r2_entry.set_single_rule(remaining_rules[0]);
            assigned_rules.insert(remaining_rules[0]);
            unique_mappings++;
            // std::cout << "Sub-rule " << sub_rule_id << " → Rule " << remaining_rules[0] << " (unique)" << std::endl;
            
        } else {
            // Multiple unassigned rules → linked list
            r2_entry.set_multiple_rules(remaining_rules);
            for (int rule_id : remaining_rules) {
                assigned_rules.insert(rule_id);
            }
            linked_list_mappings++;
            // std::cout << "Sub-rule " << sub_rule_id << " → " << remaining_rules.size() << " rules (linked list)" << std::endl;
        }
    }
    
    preprocessed_ = true;
    
    // Print optimization statistics
    std::cout << "\n========== FIDAS OPTIMIZATION RESULTS ==========" << std::endl;
    std::cout << "FIDAS Rule Database preprocessed: " 
              << rules_.size() << " rules, " 
              << string_to_rules_.size() << " unique strings" << std::endl;
    std::cout << "R2-table optimization statistics:" << std::endl;
    std::cout << "  - Unique mappings: " << unique_mappings << std::endl;
    std::cout << "  - Null mappings: " << null_mappings << std::endl;
    std::cout << "  - Linked list mappings: " << linked_list_mappings << std::endl;
    std::cout << "  - Total assigned rules: " << assigned_rules.size() << " / " << rules_.size() << std::endl;
    std::cout << "  - Optimization ratio: " << (float)unique_mappings / (unique_mappings + linked_list_mappings) * 100.0f << "%" << std::endl;
    std::cout << "R2-table and R1-table built according to FIDAS algorithm" << std::endl;
}

const std::vector<int>& FidasRuleDatabase::get_rules_requiring_string(int string_id) const {
    static const std::vector<int> empty_vector;
    auto it = string_to_rules_.find(string_id);
    return (it != string_to_rules_.end()) ? it->second : empty_vector;
}

// FIDAS Step 1: Rule ID lookup using R2-table
// std::vector<int> FidasRuleDatabase::get_rule_ids_for_sub_rule(int sub_rule_id) const {
//     std::vector<int> rule_ids;
    
//     int hash_index = hash_sub_rule_id(sub_rule_id);
//     int original_index = hash_index;
    
//     // Linear probing to find the correct entry
//     do {
//         const R2TableEntry& entry = r2_table_[hash_index];
        
//         if (entry.is_empty()) {
//             break; // Sub-rule not found
//         }
        
//         // In a real implementation, we'd need to store the sub-rule ID to verify
//         // For now, we assume the hash points to the correct entry
//         if (entry.has_multiple_rules()) {
//             rule_ids = entry.get_linked_rules();
//         } else {
//             int rule_id = entry.get_rule_id();
//             if (rule_id >= 0) {
//                 rule_ids.push_back(rule_id);
//             }
//         }
//         break; // Found the entry
        
//         hash_index = (hash_index + 1) % R2_TABLE_SIZE;
//     } while (hash_index != original_index);
    
//     return rule_ids;
// }

const R2TableEntry& FidasRuleDatabase::get_r2_table_entry(int sub_rule_id) const {
    int hash_index = hash_sub_rule_id(sub_rule_id);
    int original_index = hash_index;
    
    // Linear probing to find the correct entry
    do {
        const R2TableEntry& entry = r2_table_[hash_index];
        
        // For optimized FIDAS mapping, empty entries represent null mappings
        if (entry.is_empty()) {
            return entry; // Return empty entry (optimization case)
        }
        
        // TODO: Add sub-rule ID verification when R2TableEntry is extended
        // For now, assume hash points to correct entry (same as your current approach)
        return entry;
        
        hash_index = (hash_index + 1) % R2_TABLE_SIZE;
    } while (hash_index != original_index);
    
    // Return empty entry if not found (shouldn't happen in well-designed system)
    static const R2TableEntry empty_entry;
    return empty_entry;
}


// FIDAS Step 2: Sub-rule ID matching using R1-table
bool FidasRuleDatabase::check_rule_match(int rule_id, const std::unordered_set<int>& matched_sub_rules) const {
    if (rule_id < 0 || rule_id >= R1_TABLE_SIZE) {
        return false;
    }
    
    const R1TableEntry& r1_entry = r1_table_[rule_id];
    std::vector<int> required_sub_rules = r1_entry.get_sub_rules();
    
    // Check if all required sub-rules are matched
    for (int required_sub_rule : required_sub_rules) {
        if (matched_sub_rules.find(required_sub_rule) == matched_sub_rules.end()) {
            return false; // Missing required sub-rule
        }
    }
    
    return required_sub_rules.size() > 0; // Rule matches if it has requirements and all are met
}

const FidasRule* FidasRuleDatabase::get_rule(int rule_id) const {
    auto it = rules_.find(rule_id);
    return (it != rules_.end()) ? &it->second : nullptr;
}

std::vector<int> FidasRuleDatabase::get_all_rule_ids() const {
    std::vector<int> rule_ids;
    rule_ids.reserve(rules_.size());
    for (const auto& pair : rules_) {
        rule_ids.push_back(pair.first);
    }
    return rule_ids;
}

void FidasRuleDatabase::print_r2_table_stats() const {
    int empty_entries = 0;
    int single_rule_entries = 0;
    int multi_rule_entries = 0;
    
    for (int i = 0; i < R2_TABLE_SIZE; i++) {
        const R2TableEntry& entry = r2_table_[i];
        if (entry.is_empty()) {
            empty_entries++;
        } else if (entry.has_multiple_rules()) {
            multi_rule_entries++;
        } else {
            single_rule_entries++;
        }
    }
    
    std::cout << "R2-table Statistics:" << std::endl;
    std::cout << "  Total entries: " << R2_TABLE_SIZE << std::endl;
    std::cout << "  Empty entries: " << empty_entries << std::endl;
    std::cout << "  Single rule entries: " << single_rule_entries << std::endl;
    std::cout << "  Multi-rule entries: " << multi_rule_entries << std::endl;
    std::cout << "  Load factor: " << std::fixed << std::setprecision(2) 
              << (double)(single_rule_entries + multi_rule_entries) / R2_TABLE_SIZE * 100.0 << "%" << std::endl;
}

void FidasRuleDatabase::print_r1_table_stats() const {
    int empty_entries = 0;
    int populated_entries = 0;
    int total_sub_rules = 0;
    
    for (int i = 0; i < R1_TABLE_SIZE; i++) {
        const R1TableEntry& entry = r1_table_[i];
        if (entry.count == 0) {
            empty_entries++;
        } else {
            populated_entries++;
            total_sub_rules += entry.count;
        }
    }
    
    std::cout << "R1-table Statistics:" << std::endl;
    std::cout << "  Total entries: " << R1_TABLE_SIZE << std::endl;
    std::cout << "  Empty entries: " << empty_entries << std::endl;
    std::cout << "  Populated entries: " << populated_entries << std::endl;
    std::cout << "  Total sub-rules: " << total_sub_rules << std::endl;
    if (populated_entries > 0) {
        std::cout << "  Avg sub-rules per rule: " << std::fixed << std::setprecision(2)
                  << (double)total_sub_rules / populated_entries << std::endl;
    }
}

// --- FidasRuleLookupProcessor Implementation ---

FidasRuleLookupProcessor::FidasRuleLookupProcessor(const FidasRuleDatabase& db) : rule_db_(db) {
    if (!rule_db_.is_preprocessed()) {
        std::cerr << "Warning: FidasRuleLookupProcessor initialized with non-preprocessed database." << std::endl;
    }
}

// std::set<int> FidasRuleLookupProcessor::process_packet(const std::vector<int>& matched_string_ids) const {
//     auto start_time = std::chrono::high_resolution_clock::now();
    
//     std::set<int> triggered_sids;
//     std::unordered_set<int> candidate_rules; // Rules that might be triggered
//     std::unordered_set<int> matched_sub_rules(matched_string_ids.begin(), matched_string_ids.end());
    
//     // FIDAS Step 1: Rule ID lookup using R2-table
//     // For each matched sub-rule (string ID), find all rules that require it
//     for (int sub_rule_id : matched_string_ids) {
//         total_r2_table_lookups_++;
//         std::vector<int> rule_ids = rule_db_.get_rule_ids_for_sub_rule(sub_rule_id);
//         for (int rule_id : rule_ids) {
//             candidate_rules.insert(rule_id);
//         }
//     }
    
//     // FIDAS Step 2: Sub-rule ID matching using R1-table
//     // For each candidate rule, check if all required sub-rules are matched
//     for (int rule_id : candidate_rules) {
//         total_r1_table_checks_++;
        
//         if (rule_db_.check_rule_match(rule_id, matched_sub_rules)) {
//             const FidasRule* rule = rule_db_.get_rule(rule_id);
//             if (rule) {
//                 triggered_sids.insert(rule->sid);
//             }
//         }
//     }
    
//     auto end_time = std::chrono::high_resolution_clock::now();
//     auto processing_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
//     // Update performance statistics
//     total_lookup_time_ += processing_time;
//     total_packets_processed_++;
//     total_string_matches_processed_ += matched_string_ids.size();
//     total_rules_evaluated_ += candidate_rules.size();
//     total_rules_triggered_ += triggered_sids.size();
    
//     return triggered_sids;
// }

std::set<int> FidasRuleLookupProcessor::process_packet(
    const std::vector<int>& matched_sub_rule_ids) const {
    
    std::set<int> triggered_sids;
    std::unordered_set<int> candidate_rules;
    std::unordered_set<int> matched_sub_rules(matched_sub_rule_ids.begin(), 
                                              matched_sub_rule_ids.end());

    // auto start_time = std::chrono::high_resolution_clock::now();
    
    // FIDAS Step 1: Optimized R2-table lookup
    for (int sub_rule_id : matched_sub_rule_ids) {
        total_r2_table_lookups_++;
        
        // Use optimized R2-table entry directly
        // std::vector<int> rule_ids = rule_db_.get_rule_ids_for_sub_rule(sub_rule_id);
        const auto& r2_entry = rule_db_.get_r2_table_entry(sub_rule_id);
        
        if (r2_entry.is_empty()) {
            // Optimization: null mapping for non-unique sub-rules
            // null_mapping_skips_++;
            continue;
        }
        
        if (r2_entry.has_multiple_rules()) {
            // Linked list case
            for (int rule_id : r2_entry.get_linked_rules()) {
                candidate_rules.insert(rule_id);
            }
            // linked_list_lookups_++;
        } else {
            // Unique mapping case
            candidate_rules.insert(r2_entry.get_rule_id());
            // unique_mapping_hits_++;
        }
    }
    
    // FIDAS Step 2: R1-table verification (unchanged)
    for (int rule_id : candidate_rules) {
        total_r1_table_checks_++;
        
        if (rule_db_.check_rule_match(rule_id, matched_sub_rules)) {
            const FidasRule* rule = rule_db_.get_rule(rule_id);
            if (rule) {
                triggered_sids.insert(rule->sid);
            }
        }
    }
    
    // Update statistics...
    return triggered_sids;
}


// Print detailed per-packet analysis
void FidasRuleLookupProcessor::print_packet_analysis(const PacketResult& result, const std::string& packet_name) {
    std::cout << "\n=== COMPREHENSIVE PACKET ANALYSIS";
    if (!packet_name.empty()) {
        std::cout << " (" << packet_name << ")";
    }
    std::cout << " ===" << std::endl;
    
    // Basic Input/Output metrics
    std::cout << "\n--- INPUT/OUTPUT SUMMARY ---" << std::endl;
    std::cout << "Input strings matched: " << result.num_matched_strings << std::endl;
    std::cout << "Unique strings (deduplicated): " << result.num_unique_strings << std::endl;
    std::cout << "Total rule IDs from R2-table: " << result.total_rule_ids_from_r2 << std::endl;
    std::cout << "Candidate rules (R2-table): " << result.num_candidate_rules << std::endl;
    std::cout << "Rules evaluated (R1-table): " << result.num_rules_evaluated << std::endl;
    std::cout << "Rules triggered: " << result.num_rules_triggered << std::endl;
    std::cout << "SIDs triggered: " << result.triggered_sids.size() << std::endl;
    
    // Performance metrics
    std::cout << "\n--- PERFORMANCE BREAKDOWN ---" << std::endl;
    std::cout << "Total processing time: " << result.processing_time.count() << " μs" << std::endl;
    std::cout << "  R2-table lookup time: " << result.r2_lookup_time.count() << " μs (" 
              << std::fixed << std::setprecision(1) 
              << (result.processing_time.count() > 0 ? 
                  100.0 * result.r2_lookup_time.count() / result.processing_time.count() : 0.0) 
              << "%)" << std::endl;
    std::cout << "  R1-table check time: " << result.r1_check_time.count() << " μs (" 
              << std::fixed << std::setprecision(1) 
              << (result.processing_time.count() > 0 ? 
                  100.0 * result.r1_check_time.count() / result.processing_time.count() : 0.0) 
              << "%)" << std::endl;
    std::cout << "R2-table lookups performed: " << result.num_r2_lookups << std::endl;
    std::cout << "R1-table checks performed: " << result.num_r1_checks << std::endl;
    
    // Enhanced R2-table Analysis
    std::cout << "\n--- R2-TABLE EFFICIENCY ANALYSIS ---" << std::endl;
    std::cout << "R2 deduplication ratio: " << std::fixed << std::setprecision(4) 
              << result.r2_deduplication_ratio << " (" 
              << result.total_rule_ids_from_r2 << " -> " << result.num_candidate_rules 
              << " rules)" << std::endl;
    std::cout << "String-to-rule expansion: " << std::fixed << std::setprecision(2) 
              << result.string_to_rule_expansion << "x" << std::endl;
    std::cout << "Max rule frequency: " << result.max_rule_frequency 
              << " (max times any rule appeared)" << std::endl;
    std::cout << "Avg rule frequency: " << std::fixed << std::setprecision(2) 
              << result.avg_rule_frequency << std::endl;
    std::cout << "Rules with single match: " << result.rules_with_single_match << std::endl;
    std::cout << "Rules with multiple matches: " << result.rules_with_multiple_matches << std::endl;
    
    // Analysis ratios
    std::cout << "\n--- ALGORITHM EFFICIENCY RATIOS ---" << std::endl;
    std::cout << "Rule trigger rate: " << std::fixed << std::setprecision(4) 
              << result.rule_trigger_rate << " (" 
              << result.num_rules_triggered << "/" << result.num_rules_evaluated << ")" << std::endl;
    std::cout << "Rule filtering efficiency: " << std::fixed << std::setprecision(4) 
              << result.rule_filtering_efficiency << std::endl;
    std::cout << "R2-to-R1 ratio: " << std::fixed << std::setprecision(2) 
              << result.r2_to_r1_ratio << " (R1 checks per R2 lookup)" << std::endl;
    
    // Rule requirement distribution
    std::cout << "\n--- RULE REQUIREMENT DISTRIBUTION ---" << std::endl;
    if (result.max_strings_per_rule > 0) {
        std::cout << "Min strings per rule: " << result.min_strings_per_rule << std::endl;
        std::cout << "Max strings per rule: " << result.max_strings_per_rule << std::endl;
        std::cout << "Avg strings per rule: " << std::fixed << std::setprecision(2) 
                  << result.avg_strings_per_rule << std::endl;
        std::cout << "Rules requiring single string: " << result.rules_requiring_single_string << std::endl;
        std::cout << "Rules requiring multiple strings: " << result.rules_requiring_multiple_strings << std::endl;
    }
    
    // String analysis (top contributors)
    if (!result.string_to_rule_count.empty()) {
        std::cout << "\n--- TOP STRING CONTRIBUTORS (by rule count) ---" << std::endl;
        std::vector<std::pair<int, int>> sorted_strings(result.string_to_rule_count.begin(), result.string_to_rule_count.end());
        std::sort(sorted_strings.begin(), sorted_strings.end(), 
                  [](const std::pair<int, int>& a, const std::pair<int, int>& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(size_t(5), sorted_strings.size()); i++) {
            std::cout << "  String ID " << sorted_strings[i].first 
                      << " -> " << sorted_strings[i].second << " rules" << std::endl;
        }
    }
    
    // Rule frequency analysis (top frequent rules)
    if (!result.rule_frequency_map.empty()) {
        std::cout << "\n--- TOP FREQUENT RULES (from R2 lookups) ---" << std::endl;
        std::vector<std::pair<int, int>> sorted_rules(result.rule_frequency_map.begin(), result.rule_frequency_map.end());
        std::sort(sorted_rules.begin(), sorted_rules.end(), 
                  [](const std::pair<int, int>& a, const std::pair<int, int>& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min(size_t(5), sorted_rules.size()); i++) {
            std::cout << "  Rule ID " << sorted_rules[i].first 
                      << " -> " << sorted_rules[i].second << " occurrences" << std::endl;
        }
    }
    
    // Triggered SIDs
    if (!result.triggered_sids.empty()) {
        std::cout << "\n--- TRIGGERED SECURITY SIGNATURES ---" << std::endl;
        std::cout << "SIDs: ";
        bool first = true;
        for (int sid : result.triggered_sids) {
            if (!first) std::cout << ", ";
            std::cout << sid;
            first = false;
        }
        std::cout << std::endl;
    }
}



size_t FidasRuleLookupProcessor::estimate_memory_usage() const {
    // Estimate memory usage of the rule database and processor
    size_t total_size = sizeof(FidasRuleLookupProcessor);
    
    // Add estimated size of the rule database
    // This is a rough estimate - in practice you'd want more precise calculations
    total_size += rule_db_.get_rule_count() * sizeof(FidasRule);
    total_size += rule_db_.get_string_count() * sizeof(std::vector<int>);
    
    // Add R1 and R2 table sizes (these are fixed size arrays of 16K entries each)
    total_size += 16384 * sizeof(R1TableEntry);
    total_size += 16384 * sizeof(R2TableEntry);
    
    return total_size;
}

// --- FidasJsonLoader Implementation ---

// Helper function for JSON parsing (simplified)
std::string trim_json_string(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r\f\v\"");
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(" \t\n\r\f\v\"");
    std::string trimmed = str.substr(first, (last - first + 1));
    if (!trimmed.empty() && trimmed.front() == '\"' && trimmed.back() == '\"') {
        trimmed = trimmed.substr(1, trimmed.length() - 2);
    }
    return trimmed;
}

bool FidasJsonLoader::load_rule_database(FidasRuleDatabase& db, 
                                        const std::string& rule_table_path, 
                                        const std::string& string_table_path) {
    std::ifstream rule_file(rule_table_path);
    if (!rule_file.is_open()) {
        std::cerr << "Error: Could not open rule_table.json at " << rule_table_path << std::endl;
        return false;
    }
    
    // Read and parse rule_table.json
    std::stringstream rule_buffer;
    rule_buffer << rule_file.rdbuf();
    std::string rule_content = rule_buffer.str();
    rule_file.close();
    
    size_t pos = 0;
    while ((pos = rule_content.find('\"', pos)) != std::string::npos) {
        size_t end_rule_id_quote = rule_content.find('\"', pos + 1);
        if (end_rule_id_quote == std::string::npos) break;
        std::string rule_id_str = rule_content.substr(pos + 1, end_rule_id_quote - (pos + 1));
        pos = end_rule_id_quote + 1;

        int rule_id = std::stoi(rule_id_str);
        
        // Find SID
        size_t sid_key_pos = rule_content.find("\"sid\"", pos);
        if (sid_key_pos == std::string::npos) break;
        size_t sid_val_start = rule_content.find(':', sid_key_pos) + 1;
        size_t sid_val_end = rule_content.find_first_of(",}", sid_val_start);
        int sid = std::stoi(trim_json_string(rule_content.substr(sid_val_start, sid_val_end - sid_val_start)));

        // Find string IDs
        size_t str_id_key_pos = rule_content.find("\"str_ids\"", pos);
        if (str_id_key_pos == std::string::npos) break;
        size_t arr_start = rule_content.find('[', str_id_key_pos) + 1;
        size_t arr_end = rule_content.find(']', arr_start);
        std::string str_ids_part = rule_content.substr(arr_start, arr_end - arr_start);
        
        std::vector<int> patterns;
        std::stringstream ss_patterns(str_ids_part);
        std::string segment;
        while(std::getline(ss_patterns, segment, ',')) {
            patterns.push_back(std::stoi(trim_json_string(segment)));
        }
        
        db.add_rule(rule_id, sid, patterns);
        pos = arr_end;
    }
    
    db.finalize_preprocessing();
    return true;
}

std::unordered_map<std::string, std::vector<int>> 
FidasJsonLoader::load_packet_matches(const std::string& matched_ids_path) {
    std::unordered_map<std::string, std::vector<int>> packet_matches;
    std::ifstream match_file(matched_ids_path);
    
    if (!match_file.is_open()) {
        std::cerr << "Error: Could not open matched_ids.json at " << matched_ids_path << std::endl;
        return packet_matches;
    }
    
    std::stringstream match_buffer;
    match_buffer << match_file.rdbuf();
    std::string match_content = match_buffer.str();
    match_file.close();

    size_t pos = 0;
    while ((pos = match_content.find('\"', pos)) != std::string::npos) {
        size_t end_pkt_name_quote = match_content.find('\"', pos + 1);
        if (end_pkt_name_quote == std::string::npos) break;
        std::string pkt_name = match_content.substr(pos + 1, end_pkt_name_quote - (pos + 1));
        pos = end_pkt_name_quote + 1;

        size_t arr_start = match_content.find('[', pos) + 1;
        size_t arr_end = match_content.find(']', arr_start);
        if (arr_start == std::string::npos || arr_end == std::string::npos) break;
        
        std::string ids_part = match_content.substr(arr_start, arr_end - arr_start);
        std::vector<int> matched_ids;
        std::stringstream ss_ids(ids_part);
        std::string segment;
        while(std::getline(ss_ids, segment, ',')) {
            if (!segment.empty()) {
                matched_ids.push_back(std::stoi(trim_json_string(segment)));
            }
        }
        packet_matches[pkt_name] = matched_ids;
        pos = arr_end;
    }
    
    return packet_matches;
}

// --- AlgorithmComparator Implementation ---

FidasRuleLookupProcessor::PerformanceStats FidasRuleLookupProcessor::get_performance_stats() const {
    PerformanceStats stats;
    stats.total_lookup_time = total_lookup_time_;
    stats.total_packets_processed = total_packets_processed_;
    stats.total_string_matches_processed = total_string_matches_processed_;
    stats.total_rules_evaluated = total_rules_evaluated_;
    stats.total_rules_triggered = total_rules_triggered_;
    stats.total_r2_table_lookups = total_r2_table_lookups_;
    stats.total_r1_table_checks = total_r1_table_checks_;
    
    stats.avg_processing_time_per_packet_us = 
        total_packets_processed_ > 0 ? 
        static_cast<double>(total_lookup_time_.count()) / total_packets_processed_ : 0.0;
    
    stats.avg_rules_evaluated_per_packet = 
        total_packets_processed_ > 0 ? 
        static_cast<double>(total_rules_evaluated_) / total_packets_processed_ : 0.0;
    
    stats.rule_trigger_rate = 
        total_rules_evaluated_ > 0 ? 
        static_cast<double>(total_rules_triggered_) / total_rules_evaluated_ : 0.0;
    
    stats.avg_r2_lookups_per_packet = 
        total_packets_processed_ > 0 ? 
        static_cast<double>(total_r2_table_lookups_) / total_packets_processed_ : 0.0;
    
    stats.avg_r1_checks_per_packet = 
        total_packets_processed_ > 0 ? 
        static_cast<double>(total_r1_table_checks_) / total_packets_processed_ : 0.0;
    
    return stats;
}

void FidasRuleLookupProcessor::reset_performance_stats() {
    total_lookup_time_ = std::chrono::microseconds{0};
    total_packets_processed_ = 0;
    total_string_matches_processed_ = 0;
    total_rules_evaluated_ = 0;
    total_rules_triggered_ = 0;
    total_r2_table_lookups_ = 0;
    total_r1_table_checks_ = 0;
}

void AlgorithmComparator::compare_algorithms(
    const std::unordered_map<std::string, std::vector<int>>& packet_data,
    const FidasRuleDatabase& rule_db,
    std::vector<ComparisonResult>& results) {
    
    // This function will be extended to compare multiple algorithms
    // For now, it provides a framework for FIDAS algorithm testing
    
    FidasRuleLookupProcessor fidas_processor(rule_db);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::set<int> all_triggered_sids;
    for (const auto& packet_entry : packet_data) {
        const std::vector<int>& matched_strings = packet_entry.second;
        std::set<int> packet_sids = fidas_processor.process_packet(matched_strings);
        all_triggered_sids.insert(packet_sids.begin(), packet_sids.end());
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    ComparisonResult fidas_result;
    fidas_result.algorithm_name = "FIDAS Rule Lookup";
    fidas_result.total_packets = packet_data.size();
    fidas_result.total_triggered_rules = all_triggered_sids.size();
    fidas_result.total_processing_time = total_time;
    fidas_result.preprocessing_time = std::chrono::microseconds{0}; // Minimal for FIDAS
    fidas_result.memory_usage_bytes = fidas_processor.estimate_memory_usage();
    fidas_result.avg_time_per_packet_us = 
        packet_data.size() > 0 ? static_cast<double>(total_time.count()) / packet_data.size() : 0.0;
    fidas_result.results_match_reference = true; // This is our reference
    
    results.push_back(fidas_result);
}










