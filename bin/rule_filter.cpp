#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>
#include "bloom_filter.hpp"

using json = nlohmann::json;

int main() {
    // Load JSON files
    json ruleTableJson, stringTableJson, matchTableJson;

    try {
        std::ifstream ruleFile("rule_table.json");
        if (!ruleFile.is_open()) {
            throw std::runtime_error("Unable to open rule_table.json");
        }
        ruleFile >> ruleTableJson;

        std::ifstream stringFile("string_table.json");
        if (!stringFile.is_open()) {
            throw std::runtime_error("Unable to open string_table.json");
        }
        stringFile >> stringTableJson;

        std::ifstream matchFile("matched_ids.json");
        if (!matchFile.is_open()) {
            throw std::runtime_error("Unable to open matched_ids.json");
        }
        matchFile >> matchTableJson;
    } catch (const std::exception& e) {
        std::cerr << "Error reading JSON files: " << e.what() << std::endl;
        return 1;
    }

    // Debug Output
    // std::cout << "Rule Table JSON: " << ruleTableJson.dump(4) << std::endl;
    // std::cout << "String Table JSON: " << stringTableJson.dump(4) << std::endl;
    // std::cout << "Match Table JSON: " << matchTableJson.dump(4) << std::endl;

    // Build Bloom Filter Array
    BloomFilterArray bloomArray(ruleTableJson.size() + 1);
    
    try {
        for (const auto& item : ruleTableJson.items()) {
            int ruleId = std::stoi(item.key());
            const auto& patterns = item.value().at("str_id");
            bloomArray.add(ruleId, patterns.get<std::vector<int>>());
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing rule table: " << e.what() << std::endl;
        return 1;
    }

    // Process match table
    size_t count = 0;
    size_t max = 0;
    std::unordered_set<int> filteredIds;
    std::unordered_set<int> nonFilteredIds;

    try {
        for (const auto& packet : matchTableJson.items()) {
            int pktId = std::stoi(packet.key());
            const auto& strIds = packet.value();
            std::unordered_map<int, std::vector<int>> bloomTable;

            for (const auto& strIdValue : strIds) {
                int strId = strIdValue.get<int>(); // Ensure strId is an int
                std::string strIdStr = std::to_string(strId); // Convert to string
                if (stringTableJson.contains(strIdStr)) {
                    int ruleId = stringTableJson[strIdStr]["rid"].get<int>();
                    bloomTable[ruleId].push_back(strId);
                } else {
                    std::cerr << "Warning: stringTableJson does not contain key for strId " << strId << std::endl;
                }
            }

            std::unordered_map<int, std::unordered_set<int>> filteredRules;
            for (const auto& [ruleId, strIds] : bloomTable) {
                BloomFilter bloomFilter(bloomArray.filters[ruleId].getSize());
                for (const auto& strId : strIds) {
                    bloomFilter.add(strId);
                }

                if (bloomArray.xorOperation(ruleId, bloomFilter)) {
                    filteredRules[ruleId].insert(strIds.begin(), strIds.end());
                }
            }

            for (const auto& [ruleId, _] : bloomTable) {
                nonFilteredIds.insert(ruleId);
            }
            for (const auto& [ruleId, _] : filteredRules) {
                filteredIds.insert(ruleId);
            }

            count += filteredRules.size();
            max = std::max(max, filteredRules.size());
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing match table: " << e.what() << std::endl;
        return 1;
    }

    // Print results
    std::cout << "Number of non-filtered rules: " << nonFilteredIds.size() << std::endl;
    std::cout << "Number of filtered rules: " << filteredIds.size() << std::endl;
    std::cout << "Filtered rules: ";
    for (const auto& id : filteredIds) {
        std::cout << id << " ";
    }
    std::cout << std::endl;

    if (!matchTableJson.empty()) {
        std::cout << "Per packet analysis" << std::endl;
        std::cout << "Average number of rules matched: " << static_cast<double>(count) / matchTableJson.size() << std::endl;
        std::cout << "Maximum number of rules matched: " << max << std::endl;
    }

    return 0;
}

