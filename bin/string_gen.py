from idstools import rule
import json
import re

# file = "eternalblue_rule.rules"
file = "snort3-community.rules"

def convert_format(hex_string):
    result = bytearray()  # Using bytearray to efficiently build the result byte string
    i = 0
    while i < len(hex_string):
        if hex_string[i] == '|':
            i += 1
            start = i
            while i < len(hex_string) and hex_string[i] != '|':
                i += 1
            # Process the enclosed segment
            part = hex_string[start:i]
            if all(c in '0123456789ABCDEFabcdef ' for c in part):
                # Convert hex string to bytes
                hex_values = part.split()
                for hex_value in hex_values:
                    result.extend(bytes.fromhex(hex_value))
            else:
                # Handle non-hex segments as ASCII
                result.extend(part.encode('utf-8'))
        else:
            # Handle non-enclosed parts
            result.append(ord(hex_string[i]))
        i += 1
    return bytes(result)

def write_pcre_to_file(pcre_dict, filename):
    with open(filename, 'w') as file:
        for key, value in pcre_dict.items():
            pattern = value['string']#.strip('"')  # Strip quotes
            file.write(f"{key}:{pattern}\n")

strings = [] # strings extracted from rules
string_table = {}
rule_table = {}
pattern = r'"([^"]*)"'
r_id = 0
count=0

for rule in rule.parse_file(file):
    if "content" in rule:
        content_values = [option['value'] for option in rule['options'] if option['name'] == 'content']
        r_id += 1
        rule_table[r_id] = {'sid': rule.sid,
                            'str_id': []}
        for value in content_values:
            match  = re.search(pattern, value)
            patt = match.group(1)

            if len(patt) > 1:
                string = convert_format(patt)

                if match and len(string) > 1:
                    count += 1
                    strings.append(string)
                    string_table[count] = {'sid': rule.sid,
                                          'string': str(string)[2:-1],
                                          'rid': r_id}
                    rule_table[r_id]['str_id'].append(count)
with open('rule_table.json', 'w') as rule_file:
    json.dump(rule_table, rule_file, indent=4)

# Saving string_table to JSON file
with open('string_table.json', 'w') as string_file:
    json.dump(string_table, string_file, indent=4)
                    
write_pcre_to_file(string_table, 'literals.txt')
