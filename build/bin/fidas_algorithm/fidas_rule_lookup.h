#ifndef FIDAS_RULE_LOOKUP_H
#define FIDAS_RULE_LOOKUP_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <string>
#include <chrono>
#include <cstdint>

// FIDAS R2-table entry structure according to the paper
struct R2TableEntry {
    uint16_t empty_bit : 1;    // Indicates if entry is empty
    uint16_t link_bit : 1;     // Indicates if sub-rule maps to multiple rules
    uint16_t content : 14;     // Rule ID directly or address of linked list
    
    // For cases where sub-rule maps to multiple rules (when link_bit = 1)
    std::vector<int> linked_rules;
    
    R2TableEntry() : empty_bit(1), link_bit(0), content(0) {}
    
    bool is_empty() const { return empty_bit == 1; }
    bool has_multiple_rules() const { return link_bit == 1; }
    int get_rule_id() const { return has_multiple_rules() ? -1 : static_cast<int>(content); }
    const std::vector<int>& get_linked_rules() const { return linked_rules; }

    
    void set_single_rule(int rule_id) {
        empty_bit = 0;
        link_bit = 0;
        content = static_cast<uint16_t>(rule_id);
        linked_rules.clear();
    }
    
    void set_multiple_rules(const std::vector<int>& rules) {
        empty_bit = 0;
        link_bit = 1;
        content = 0; // Address would be stored here in hardware
        linked_rules = rules;
    }

    void set_empty() {
        empty_bit = 1;
        link_bit = 0;
        content = 0;
        linked_rules.clear();
    }
};

// FIDAS R1-table entry structure according to the paper
struct R1TableEntry {
    static const int MAX_SUB_RULES = 8;
    int sub_rule_ids[MAX_SUB_RULES];  // Each field is 15-bit in paper, using int for simplicity
    int count;                        // Number of valid sub-rules
    
    R1TableEntry() : count(0) {
        for (int i = 0; i < MAX_SUB_RULES; i++) {
            sub_rule_ids[i] = -1;  // -1 indicates invalid
        }
    }
    
    void add_sub_rule(int sub_rule_id) {
        if (count < MAX_SUB_RULES) {
            sub_rule_ids[count++] = sub_rule_id;
        }
    }
    
    std::vector<int> get_sub_rules() const {
        std::vector<int> result;
        for (int i = 0; i < count; i++) {
            result.push_back(sub_rule_ids[i]);
        }
        return result;
    }
};

// FIDAS Rule Structure
struct FidasRule {
    int rule_id;
    int sid;                                    // Signature ID for alerting
    std::vector<int> required_string_ids;      // All string IDs that must be matched (sub-rules)
    std::unordered_set<int> required_set;      // For faster lookup
    int min_required_matches;                  // Minimum number of strings needed (for partial matching)
    
    FidasRule() : rule_id(-1), sid(-1), min_required_matches(0) {}
    
    FidasRule(int rid, int signature_id, const std::vector<int>& strings, int min_matches = -1) 
        : rule_id(rid), sid(signature_id), required_string_ids(strings),
          required_set(strings.begin(), strings.end()) {
        min_required_matches = (min_matches == -1) ? strings.size() : min_matches;
    }
};

// FIDAS Rule Database for lookup operations
class FidasRuleDatabase {
private:
    std::unordered_map<int, FidasRule> rules_;                    // rule_id -> FidasRule
    std::unordered_map<int, std::vector<int>> string_to_rules_;   // string_id -> list of rule_ids that need this string
    
    // FIDAS-specific tables according to the paper
    static const int R2_TABLE_SIZE = 16384;  // 16K entries as mentioned in paper
    static const int R1_TABLE_SIZE = 16384;  // 16K entries as mentioned in paper
    
    R2TableEntry r2_table_[R2_TABLE_SIZE];   // R2-table: sub-rule ID -> rule ID mapping
    R1TableEntry r1_table_[R1_TABLE_SIZE];   // R1-table: rule ID -> required sub-rule IDs
    
    bool preprocessed_;
    
    // Hash function for R2-table (simple modulo for now)
    int hash_sub_rule_id(int sub_rule_id) const {
        return abs(sub_rule_id) % R2_TABLE_SIZE;
    }
    
public:
    FidasRuleDatabase();
    
    // Add a rule to the database
    void add_rule(int rule_id, int sid, const std::vector<int>& required_strings, int min_matches = -1);
    
    // Finalize preprocessing - build R2-table and R1-table according to FIDAS algorithm
    void finalize_preprocessing();
    
    // Check if database is ready for lookup
    bool is_preprocessed() const { return preprocessed_; }
    
    // FIDAS-specific lookup functions
    // Step 1: Rule ID lookup using R2-table
    // std::vector<int> get_rule_ids_for_sub_rule(int sub_rule_id) const;

    const R2TableEntry& get_r2_table_entry(int sub_rule_id) const;
    
    // Step 2: Sub-rule ID matching using R1-table
    bool check_rule_match(int rule_id, const std::unordered_set<int>& matched_sub_rules) const;
    
    // Get all rules that require a specific string (legacy compatibility)
    const std::vector<int>& get_rules_requiring_string(int string_id) const;
    
    // Get rule by ID
    const FidasRule* get_rule(int rule_id) const;
    
    // Get all rule IDs
    std::vector<int> get_all_rule_ids() const;
    
    // Statistics
    size_t get_rule_count() const { return rules_.size(); }
    size_t get_string_count() const { return string_to_rules_.size(); }
    
    // Debug functions for FIDAS tables
    void print_r2_table_stats() const;
    void print_r1_table_stats() const;
};

// FIDAS Rule Lookup Processor - Implements the two-step FIDAS algorithm
class FidasRuleLookupProcessor {
private:
    const FidasRuleDatabase& rule_db_;
    
    // Performance tracking
    mutable std::chrono::microseconds total_lookup_time_{0};
    mutable size_t total_packets_processed_{0};
    mutable size_t total_string_matches_processed_{0};
    mutable size_t total_rules_evaluated_{0};
    mutable size_t total_rules_triggered_{0};
    mutable size_t total_r2_table_lookups_{0};
    mutable size_t total_r1_table_checks_{0};
    
public:
    explicit FidasRuleLookupProcessor(const FidasRuleDatabase& db);
    
    // Process a packet's matched strings using the two-step FIDAS algorithm
    // Step 1: Rule ID lookup using R2-table
    // Step 2: Sub-rule ID matching using R1-table
    std::set<int> process_packet(const std::vector<int>& matched_string_ids) const;
    
    // Alternative: Process packet and return detailed per-packet analysis
    struct PacketResult {
        // Basic results
        std::set<int> triggered_sids;
        std::vector<int> triggered_rule_ids;
        
        // Per-packet analysis metrics
        size_t num_matched_strings;           // Number of input string matches
        size_t num_unique_strings;            // Number of unique strings (deduplication)
        size_t num_candidate_rules;           // Rules identified in Step 1 (R2-table)
        size_t num_rules_evaluated;           // Rules checked in Step 2 (R1-table)
        size_t num_rules_triggered;           // Rules that fully matched
        size_t num_r2_lookups;                // R2-table lookups performed
        size_t num_r1_checks;                 // R1-table checks performed
        
        // Enhanced analysis metrics
        size_t total_rule_ids_from_r2;        // Total rule IDs before deduplication
        double r2_deduplication_ratio;        // Reduction ratio from R2 lookups
        size_t max_rule_frequency;            // Max times any rule appeared from R2 lookups
        double avg_rule_frequency;            // Average frequency of rules from R2 lookups
        size_t rules_with_single_match;       // Rules that appeared only once in R2 results
        size_t rules_with_multiple_matches;   // Rules that appeared multiple times
        
        // Performance metrics
        std::chrono::microseconds processing_time;
        std::chrono::microseconds r2_lookup_time;
        std::chrono::microseconds r1_check_time;
        
        // Analysis ratios
        double rule_trigger_rate;             // triggered / evaluated
        double rule_filtering_efficiency;     // 1 - (evaluated / total_rules)
        double r2_to_r1_ratio;               // r1_checks / r2_lookups
        double string_to_rule_expansion;      // total_rule_ids_from_r2 / num_matched_strings
        
        // String analysis
        std::vector<int> unique_candidate_rules;  // All unique rule IDs from R2-table
        std::unordered_map<int, int> string_to_rule_count; // string_id -> num_rules_requiring_it
        std::unordered_map<int, int> rule_frequency_map;   // rule_id -> frequency from R2 lookups
        
        // Detailed breakdowns
        size_t min_strings_per_rule;          // Minimum strings pointing to any candidate rule  
        size_t max_strings_per_rule;          // Maximum strings pointing to any candidate rule
        double avg_strings_per_rule;          // Average strings per candidate rule
        size_t rules_requiring_single_string; // Rules that need only one matched string
        size_t rules_requiring_multiple_strings; // Rules that need multiple matched strings
    };
    
    PacketResult process_packet_detailed(const std::vector<int>& matched_string_ids) const;
    
    // Print detailed per-packet analysis
    static void print_packet_analysis(const PacketResult& result, const std::string& packet_name = "");
    
    // Batch analysis for multiple packets
    struct BatchAnalysisResult {
        std::vector<PacketResult> packet_results;
        size_t total_packets;
        double avg_strings_per_packet;
        double avg_candidate_rules_per_packet;
        double avg_rules_evaluated_per_packet;
        double avg_rules_triggered_per_packet;
        double overall_trigger_rate;
        double avg_filtering_efficiency;
        std::chrono::microseconds total_processing_time;
        
        // Enhanced batch metrics
        double avg_r2_lookups_per_packet;
        double avg_r1_checks_per_packet;
        double avg_r2_deduplication_ratio;
        double avg_string_to_rule_expansion;
        size_t total_unique_sids_triggered;
        size_t packets_with_triggers;
        double packet_trigger_rate;  // percentage of packets that triggered any rules
        
        // Distribution statistics
        size_t min_strings_per_packet;
        size_t max_strings_per_packet;
        size_t min_rules_triggered_per_packet;
        size_t max_rules_triggered_per_packet;
        double std_dev_processing_time;
    };
    
    BatchAnalysisResult analyze_packets_batch(const std::unordered_map<std::string, std::vector<int>>& packet_data) const;
    
    // Print comprehensive batch analysis report
    static void print_batch_analysis(const BatchAnalysisResult& result);
    
    // Performance statistics
    struct PerformanceStats {
        std::chrono::microseconds total_lookup_time;
        size_t total_packets_processed;
        size_t total_string_matches_processed;
        size_t total_rules_evaluated;
        size_t total_rules_triggered;
        size_t total_r2_table_lookups;  // FIDAS-specific: R2-table lookups
        size_t total_r1_table_checks;   // FIDAS-specific: R1-table checks
        double avg_processing_time_per_packet_us;
        double avg_rules_evaluated_per_packet;
        double rule_trigger_rate;
        double avg_r2_lookups_per_packet;
        double avg_r1_checks_per_packet;
    };
    
    PerformanceStats get_performance_stats() const;
    void reset_performance_stats();
    
    // Memory usage estimation
    size_t estimate_memory_usage() const;
};

// Utility functions for loading from JSON files
class FidasJsonLoader {
public:
    // Load rule database from JSON files (similar to your existing format)
    static bool load_rule_database(FidasRuleDatabase& db, 
                                 const std::string& rule_table_path, 
                                 const std::string& string_table_path);
    
    // Load packet matches from matched_ids.json
    static std::unordered_map<std::string, std::vector<int>> 
    load_packet_matches(const std::string& matched_ids_path);
};

// Comparison utilities
struct ComparisonResult {
    std::string algorithm_name;
    size_t total_packets;
    size_t total_triggered_rules;
    std::chrono::microseconds total_processing_time;
    std::chrono::microseconds preprocessing_time;
    size_t memory_usage_bytes;
    double avg_time_per_packet_us;
    bool results_match_reference;
};

class AlgorithmComparator {
public:
    static void compare_algorithms(
        const std::unordered_map<std::string, std::vector<int>>& packet_data,
        const FidasRuleDatabase& rule_db,
        std::vector<ComparisonResult>& results
    );
    
    static void print_comparison_table(const std::vector<ComparisonResult>& results);
};

// Export utilities for analysis results
class FidasAnalysisExporter {
public:
    // Export packet analysis to JSON format
    static bool export_packet_analysis_json(const std::vector<FidasRuleLookupProcessor::PacketResult>& results,
                                           const std::string& output_path);
    
    // Export batch analysis to CSV format
    static bool export_batch_analysis_csv(const FidasRuleLookupProcessor::BatchAnalysisResult& result,
                                         const std::string& output_path);
    
    // Export performance comparison to JSON
    static bool export_comparison_json(const std::vector<ComparisonResult>& results,
                                     const std::string& output_path);
    
    // Export R2/R1 table statistics
    static bool export_table_statistics(const FidasRuleDatabase& db,
                                       const std::string& output_path);
};

// Real-time monitoring and alerting
class FidasRealTimeMonitor {
private:
    struct AlertThreshold {
        double max_processing_time_us;
        double max_memory_usage_mb;
        double min_filtering_efficiency;
        size_t max_rules_per_packet;
    };
    
    AlertThreshold thresholds_;
    bool monitoring_active_;
    std::chrono::steady_clock::time_point start_time_;
    
public:
    FidasRealTimeMonitor();
    
    // Configure alerting thresholds
    void set_alert_thresholds(double max_time_us, double max_memory_mb, 
                             double min_efficiency, size_t max_rules);
    
    // Start/stop monitoring
    void start_monitoring();
    void stop_monitoring();
    
    // Check packet result against thresholds
    struct AlertInfo {
        bool triggered;
        std::string alert_type;
        std::string message;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    AlertInfo check_packet_performance(const FidasRuleLookupProcessor::PacketResult& result);
    
    // Performance trending
    struct TrendAnalysis {
        std::vector<double> processing_time_trend;
        std::vector<double> memory_usage_trend;
        std::vector<double> efficiency_trend;
        double time_slope;  // positive indicates degradation
        double memory_slope;
        double efficiency_slope;
    };
    
    TrendAnalysis analyze_performance_trend(const std::vector<FidasRuleLookupProcessor::PacketResult>& recent_results);
};

// Advanced analytics and optimization suggestions
class FidasOptimizationAnalyzer {
public:
    struct OptimizationRecommendation {
        std::string category;  // "R2_TABLE", "R1_TABLE", "RULE_ORGANIZATION", "MEMORY"
        std::string description;
        double potential_improvement_percent;
        std::string implementation_effort;  // "LOW", "MEDIUM", "HIGH"
    };
    
    // Analyze rule database for optimization opportunities
    static std::vector<OptimizationRecommendation> analyze_rule_database(const FidasRuleDatabase& db);
    
    // Analyze packet processing patterns for optimization
    static std::vector<OptimizationRecommendation> analyze_processing_patterns(
        const std::vector<FidasRuleLookupProcessor::PacketResult>& results);
    
    // Suggest R2-table size optimization
    static int suggest_optimal_r2_table_size(const FidasRuleDatabase& db);
    
    // Suggest R1-table organization improvements
    static std::vector<std::string> suggest_r1_table_improvements(const FidasRuleDatabase& db);
    
    // Memory usage optimization suggestions
    struct MemoryOptimization {
        std::string technique;
        size_t estimated_savings_bytes;
        std::string description;
    };
    
    static std::vector<MemoryOptimization> suggest_memory_optimizations(const FidasRuleDatabase& db);
};

#endif // FIDAS_RULE_LOOKUP_H
