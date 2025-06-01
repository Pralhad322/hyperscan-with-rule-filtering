#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <chrono>
#include <unordered_map>
#include <nlohmann/json.hpp>

#include "fidas_algorithm/fidas_rule_lookup.h"
using json = nlohmann::json;

std::unordered_map<int, std::pair<std::vector<int>, int>> load_rule_table(const std::string& filename = "rule_table.json") {
    std::unordered_map<int, std::pair<std::vector<int>, int>> rules;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        return rules;
    }
    
    json rule_json;
    file >> rule_json;
    file.close();
    
    for (const auto& [rule_id_str, rule_data] : rule_json.items()) {
        int rule_id = std::stoi(rule_id_str);
        int sid = rule_data["sid"];
        
        // Handle both "str_ids" (array) and "str_id" (single or array) formats
        std::vector<int> string_ids;
        if (rule_data.contains("str_ids")) {
            string_ids = rule_data["str_ids"].get<std::vector<int>>();
        } else if (rule_data.contains("str_id")) {
            if (rule_data["str_id"].is_array()) {
                string_ids = rule_data["str_id"].get<std::vector<int>>();
            } else {
                string_ids.push_back(rule_data["str_id"].get<int>());
            }
        }
        
        rules[rule_id] = {string_ids, sid};
        // std::cout << "Loaded rule " << rule_id << " with SID " << sid 
        //           << " and " << string_ids.size() << " string patterns" << std::endl;
    }
    
    return rules;
}

std::unordered_map<std::string, std::vector<int>> load_packet_matches(const std::string& filename = "matched_ids.json") {
    std::unordered_map<std::string, std::vector<int>> packet_matches;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        return packet_matches;
    }
    
    json match_json;
    file >> match_json;
    file.close();
    
    for (const auto& [packet_id, matched_strings] : match_json.items()) {
        packet_matches[packet_id] = matched_strings.get<std::vector<int>>();
    }
    
    return packet_matches;
}

int main() {
    std::cout << "=== FIDAS Filter Test ===" << std::endl;
    
    // Load data
    auto rules = load_rule_table();
    auto packet_matches = load_packet_matches();
    
    std::cout << "Loaded " << rules.size() << " rules" << std::endl;
    std::cout << "Loaded " << packet_matches.size() << " packet matches" << std::endl;
    
    if (rules.empty() || packet_matches.empty()) {
        std::cerr << "No data loaded, exiting" << std::endl;
        return 1;
    }
    
    // Initialize FidasRuleLookupDatabase
    FidasRuleDatabase rule_db;
    
    // Add rules to database
    for (const auto& [rule_id, rule_info] : rules) {
        const auto& [string_ids, sid] = rule_info;
        rule_db.add_rule(rule_id, sid, string_ids);
    }
    
    rule_db.finalize_preprocessing();
    std::cout << "FIDAS rule database initialized and preprocessed" << std::endl;
    
    // Test packet processing
    FidasRuleLookupProcessor processor(rule_db);
    
    int total_triggered_rules = 0;
    int packets_processed = 0;
    std::set<int> all_triggered_sids;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Process first 10 packets for testing
    // int packet_limit = std::min(10, (int)packet_matches.size());
    for (const auto& [packet_id, matched_strings] : packet_matches) {
        // if (packets_processed >= packet_limit) break;
        
        // std::cout << "\nProcessing " << packet_id << " with " << matched_strings.size() << " matched strings: ";
        // for (int str_id : matched_strings) {
        //     std::cout << str_id << " ";
        // }
        // std::cout << std::endl;
        
        auto triggered_sids = processor.process_packet(matched_strings);
        
        // std::cout << "Triggered " << triggered_sids.size() << " rules with SIDs: ";
        // for (int sid : triggered_sids) {
        //     std::cout << sid << " ";
        // }
        // std::cout << std::endl;

        for (int sid : triggered_sids) {
            all_triggered_sids.insert(sid);
        }
        
        total_triggered_rules += triggered_sids.size();
        packets_processed++;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    
    std::cout << "\n=== FIDAS Filter Results ===" << std::endl;
    std::cout << "Packets processed: " << packets_processed << std::endl;
    std::cout << "Total rules triggered: " << total_triggered_rules << std::endl;
    std::cout << "Average rules per packet: " << (double)total_triggered_rules / packets_processed << std::endl;
    std::cout << "Processing time: " << duration << " ms" << std::endl;
    std::cout << "Packets per second: " << packets_processed / (duration / 1000.0) << std::endl;
    
    std::cout << "Total unique SIDs triggered: " << all_triggered_sids.size() << std::endl;
    std::cout << "SIDs: ";

    std::set<int> expected_sids = {41378, 42331, 42340, 42944}; // Example expected SIDs for validation

    // check if expected SIDs are in the triggered SIDs
    for (int expected_sid : expected_sids) {
        if (all_triggered_sids.find(expected_sid) != all_triggered_sids.end()) {
            std::cout << "Expected SID " << expected_sid << " was triggered." << std::endl;
        } else {
            std::cout << "Expected SID " << expected_sid << " was NOT triggered." << std::endl;
        }
    }

    for (int sid : all_triggered_sids) {
        std::cout << sid << " ";
    }
    std::cout << std::endl;

    return 0;
}
