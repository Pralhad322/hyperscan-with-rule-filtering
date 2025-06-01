# Cuckoo Hash-based Ordered Multi-String Matching Algorithm

## Functionality

This algorithm identifies matches for predefined, ordered sequences of strings (rules) within a stream of input strings (packet data). It utilizes a Cuckoo hash table to efficiently track the progress of partially matched rules. A rule is considered matched only when all its constituent strings appear in the input stream in the exact order specified by the rule definition.

The process is divided into two main phases:

1.  **Preprocessing Phase:** Rule definitions are loaded and processed. Information about each rule and how strings participate in these rules is stored. A key part of this phase is to map each string to the rules it belongs to and its position within those rules.
2.  **Packet Processing Phase:** Incoming strings are processed. The Cuckoo hash table is used to maintain the state of active rule matches, advancing them as subsequent strings in their defined order are encountered.

## Preprocessing Phase Data Structures

The `CuckooRuleDatabase` class is responsible for constructing and managing the data structures during the preprocessing phase:

1.  **`rule_definitions_` ( `std::vector<CuckooRuleInfo>` )**
    *   **Description:** This vector stores the detailed information for each rule. Each `CuckooRuleInfo` object contains:
        *   `sid` ( `int` ): The unique identifier for the rule.
        *   `defined_strings_ordered` ( `std::vector<int>` ): An ordered list of unique string identifiers that make up this rule. The order is crucial as it dictates the matching sequence.
        *   `unique_strings_set` ( `std::set<int>` ): A set of string IDs in the rule, for quick checks of string membership (though the ordered vector is primary for sequence matching).
    *   **Purpose:** Acts as the central repository for all rule specifications, including their SIDs and the ordered sequence of strings they comprise.

2.  **`string_rule_participation_` ( `std::map<int, std::vector<CuckooParticipationInfo>>` )**
    *   **Description:** This map is critical for linking individual string IDs to the rules they are part of and their specific role within those rules.
        *   **Key ( `int` ):** A unique string identifier.
        *   **Value ( `std::vector<CuckooParticipationInfo>` ):** A list of `CuckooParticipationInfo` objects. Each object details a specific rule in which the string ID (key) participates.
            *   `rule_id_index` ( `int` ): The index into the `rule_definitions_` vector, identifying the rule.
            *   `string_index_in_rule` ( `int` ): The 0-based index of this string ID within the `defined_strings_ordered` vector of the respective rule.
    *   **Purpose:** When a string is encountered during packet processing, this map allows the system to quickly find all rules that contain this string and determine if this string could potentially advance the matching progress for any of those rules.

## Packet Processing Phase Data Structures & Logic

The `CuckooPacketMatchProcessor` class uses the preprocessed data from `CuckooRuleDatabase` and a Cuckoo hash table to manage active rule matching during packet processing.

1.  **`active_rules_progress_cuckoo_table_` ( `CuckooHashTable<int, int>` )**
    *   **Description:** This is the core data structure for stateful packet processing. It's an instance of the generic `CuckooHashTable`.
        *   **Key ( `int` ):** The `rule_id_index` (index from `CuckooRuleDatabase::rule_definitions_`) of a rule that is currently being tracked as partially matched.
        *   **Value ( `int` ):** The index of the *next expected string* in that rule's `defined_strings_ordered` sequence. For example, if a rule is `[S1, S2, S3]` and `S1` has been matched, the value stored would be `1` (pointing to `S2`). If `S1` and `S2` have been matched, the value would be `2` (pointing to `S3`).
    *   **How it's used:**
        1.  **Processing an Incoming String ( `current_string_id` ):**
            a.  The `string_rule_participation_` map (from `CuckooRuleDatabase`) is queried with `current_string_id` to get all `CuckooParticipationInfo` entries associated with this string.
            b.  For each `participation_info`:
                i.  Let `rule_idx` be `participation_info.rule_id_index` and `str_idx_in_rule` be `participation_info.string_index_in_rule`.
                ii. **Case 1: String is the first in a rule ( `str_idx_in_rule == 0` )**
                    *   The algorithm attempts to insert or update an entry in `active_rules_progress_cuckoo_table_` for `rule_idx`.
                    *   The value stored will be `1` (indicating that the next expected string is the one at index 1 in this rule's definition).
                    *   If the rule only has one string (i.e., `rule_definitions_[rule_idx].defined_strings_ordered.size() == 1`), this rule is immediately considered matched. Its `sid` is added to `final_matched_sids_`.
                iii. **Case 2: String is not the first in a rule ( `str_idx_in_rule > 0` )**
                    *   The algorithm looks up `rule_idx` in `active_rules_progress_cuckoo_table_`.
                    *   If an entry exists and its value (the `next_expected_string_index`) is equal to `str_idx_in_rule`, it means the `current_string_id` is indeed the next expected string for this partially matched rule.
                        *   The entry in `active_rules_progress_cuckoo_table_` for `rule_idx` is updated. The new value becomes `str_idx_in_rule + 1`.
                        *   If this new value (`str_idx_in_rule + 1`) is equal to the total number of strings in this rule (i.e., `rule_definitions_[rule_idx].defined_strings_ordered.size()`), the rule is now fully matched. Its `sid` is added to `final_matched_sids_`, and the entry for `rule_idx` is removed from the Cuckoo hash table (as it's complete).
                    *   If no entry exists for `rule_idx`, or if the `next_expected_string_index` does not match `str_idx_in_rule`, this `current_string_id` does not advance this specific rule sequence from a previously stored state. (However, if this same `current_string_id` also happens to be the *first* string of *another* rule, or even this same rule if out of order, it would be handled by Case 1 for that context).

This Cuckoo hash-based approach allows for O(1) average time complexity for lookups, insertions, and updates of rule progress states, making it potentially very efficient for high-throughput packet processing. The worst-case scenarios for Cuckoo hashing (rehashes) are mitigated by careful hash function selection and table sizing.
