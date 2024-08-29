#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <vector>
#include <unordered_map>
#include <string>
#include <nlohmann/json.hpp>  // Include the nlohmann/json.hpp library

using json = nlohmann::json;

// Function to convert the hexadecimal strings to bytes
std::vector<uint8_t> convertFormat(const std::string& hexString) {
    std::vector<uint8_t> result;
    size_t i = 0;
    while (i < hexString.length()) {
        if (hexString[i] == '|') {
            ++i;
            size_t start = i;
            while (i < hexString.length() && hexString[i] != '|') {
                ++i;
            }
            std::string part = hexString.substr(start, i - start);
            bool isHex = std::all_of(part.begin(), part.end(), [](char c) {
                return std::isxdigit(c) || c == ' ';
            });

            if (isHex) {
                std::istringstream hexStream(part);
                std::string hexValue;
                while (hexStream >> hexValue) {
                    result.push_back(static_cast<uint8_t>(std::stoi(hexValue, nullptr, 16)));
                }
            } else {
                result.insert(result.end(), part.begin(), part.end());
            }
        } else {
            result.push_back(static_cast<uint8_t>(hexString[i]));
        }
        ++i;
    }
    return result;
}

// Function to write PCRE data to a file
void writePCREToFile(const std::unordered_map<int, json>& pcreDict, const std::string& filename) {
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    for (const auto& [key, value] : pcreDict) {
        outFile << key << ":" << value["string"].get<std::string>() << "\n";
    }
}

// Function to parse rules from the file and extract content
void parseRules(const std::string& file) {
    std::ifstream infile(file);
    if (!infile) {
        std::cerr << "Error opening rule file: " << file << std::endl;
        return;
    }

    std::unordered_map<int, json> stringTable, ruleTable;
    std::vector<std::vector<uint8_t>> strings;
    std::string line;
    
    // Updated regex pattern to match double quotes properly
    std::regex contentPattern(R"(\\\"([^\\\"]*)\\\")");

    int ruleId = 0, count = 0;
    while (std::getline(infile, line)) {
        std::smatch match;
        if (std::regex_search(line, match, contentPattern)) {
            ruleId++;
            ruleTable[ruleId] = { {"sid", ruleId}, {"str_id", json::array()} };

            for (const auto& value : match) {
                std::string patt = value.str();
                std::vector<uint8_t> stringData = convertFormat(patt);

                if (stringData.size() > 1) {
                    count++;
                    strings.push_back(stringData);
                    stringTable[count] = { {"sid", ruleId}, {"string", std::string(stringData.begin(), stringData.end())}, {"rid", ruleId} };
                    ruleTable[ruleId]["str_id"].push_back(count);
                }
            }
        }
    }

    // Convert the unordered_map to a json object for dumping
    json ruleTableJson(ruleTable);
    json stringTableJson(stringTable);

    // Write output to files
    std::ofstream ruleFile("rule_table_cpp.json");
    ruleFile << ruleTableJson.dump(4);

    std::ofstream stringFile("string_table_cpp.json");
    stringFile << stringTableJson.dump(4);

    writePCREToFile(stringTable, "literals_cpp.txt");
}

int main() {
    std::string file = "snort3-community.rules";  // File name
    parseRules(file);
    return 0;
}
