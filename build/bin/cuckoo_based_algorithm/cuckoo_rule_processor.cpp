#include "cuckoo_rule_processor.h"
#include <iostream> // For potential debug output

// Initialize static member for empty participation info
const std::vector<CuckooParticipationInfo> CuckooRuleDatabase::empty_participation_info_;

// --- CuckooRuleDatabase Methods ---

void CuckooRuleDatabase::add_rule(int rule_id, const std::vector<int>& string_ids_ordered, int sid) {
    // Store the rule definition
    rule_definitions_.emplace(rule_id, CuckooRuleInfo(sid, string_ids_ordered));

    // Populate the StringRuleParticipation map
    for (int i = 0; i < string_ids_ordered.size(); ++i) {
        int string_id = string_ids_ordered[i];
        string_rule_participation_[string_id].push_back({rule_id, i});
    }
}

void CuckooRuleDatabase::finalize_preprocessing() {
    // In this version, preprocessing primarily happens during add_rule.
    // This function can be used for future optimizations or consistency checks.
    preprocessed_ = true;
}

bool CuckooRuleDatabase::is_preprocessed() const {
    return preprocessed_;
}

std::optional<CuckooRuleInfo> CuckooRuleDatabase::get_rule_info(int rule_id) const {
    auto it = rule_definitions_.find(rule_id);
    if (it != rule_definitions_.end()) {
        return it->second;
    }
    return std::nullopt;
}

const std::vector<CuckooParticipationInfo>& CuckooRuleDatabase::get_string_participation(int string_id) const {
    auto it = string_rule_participation_.find(string_id);
    if (it != string_rule_participation_.end()) {
        return it->second;
    }
    return empty_participation_info_; // Return reference to static empty vector
}

// --- CuckooPacketMatchProcessor Methods ---

CuckooPacketMatchProcessor::CuckooPacketMatchProcessor(const CuckooRuleDatabase& db, size_t cuckoo_table_size_estimate)
    : rule_db_(db), active_rules_progress_cuckoo_table_(cuckoo_table_size_estimate) {}

std::set<int> CuckooPacketMatchProcessor::process_packet(const std::vector<int>& packet_matched_string_ids) {
    active_rules_progress_cuckoo_table_.clear(); // Clear Cuckoo table for each new packet
    std::set<int> fully_matched_sids_this_packet;

    for (int current_packet_string_id : packet_matched_string_ids) {

        // Retrieve all rules that this string ID participates in
        // This will return a vector of CuckooParticipationInfo, which contains rule_id and index_in_rule
        const auto& participations = rule_db_.get_string_participation(current_packet_string_id);

        for (const auto& participation_info : participations) {
            int eval_rule_id = participation_info.rule_id;
            int index_of_current_string_in_rule = participation_info.string_index_in_rule;

            int current_progress_index_for_eval_rule = 0; // Default: rule not active or waiting for its first string
            
            // Check if this rule is already tracked in the Cuckoo table
            // If it is, retrieve its current progress index
            std::optional<int> progress_opt = active_rules_progress_cuckoo_table_.lookup(eval_rule_id);
            
            // If the rule is not found, it means it's either not active or hasn't started processing yet
            if (progress_opt.has_value()) {
                current_progress_index_for_eval_rule = progress_opt.value();
            }

            // Order Check: Is the current packet string the one this rule is waiting for?
            if (index_of_current_string_in_rule == current_progress_index_for_eval_rule) {
                int new_progress_index = current_progress_index_for_eval_rule + 1;
                
                // Update progress in Cuckoo table
                if (!active_rules_progress_cuckoo_table_.insert_or_update(eval_rule_id, new_progress_index)) {
                    // Insertion failed (e.g. table full and no rehash implemented in this simple version)
                    // Depending on policy, could log this. For now, we just can't track this rule further for this packet.
                    // std::cerr << "Cuckoo table insertion/update failed for rule: " << eval_rule_id << std::endl;
                    continue; // Skip to next participation if update fails
                }

                // Completeness Check
                std::optional<CuckooRuleInfo> rule_details_opt = rule_db_.get_rule_info(eval_rule_id);
                if (rule_details_opt.has_value()) {
                    const CuckooRuleInfo& rule_details = rule_details_opt.value();
                    if (new_progress_index == rule_details.num_strings_in_rule) {
                        fully_matched_sids_this_packet.insert(rule_details.sid);
                        // Optional: If a rule should only match once per packet, 
                        // you might remove it from Cuckoo table here or add to a 'completed' set.
                        // active_rules_progress_cuckoo_table_.remove(eval_rule_id);
                    }
                }
            }
        }
    }
    return fully_matched_sids_this_packet;
}
