import json
from bloom_filter import BloomFilter, BloomFilterArray
import logging
from header_match import HDREngine
from hdr_match import RuleEngine

logging.basicConfig(filename='output1.log', level=logging.INFO, format='%(message)s')

def read_tables():
    # Reading rule_table.json
    with open('rule_table.json', 'r') as rule_file:
        rule_table = json.load(rule_file)

    # Reading string_table.json
    with open('string_table.json', 'r') as string_file:
        string_table = json.load(string_file)
    
    # Reading match_table.json
    with open('matched_ids.json', 'r') as match_file:
        match_table = json.load(match_file)

    return rule_table, string_table, match_table


def build_bloom_filter(rule_table):
    n = len(rule_table)
    bloom_array = BloomFilterArray(n+1)

    for value in rule_table:
        bloom_array.add(int(value), rule_table[value]['str_id'])
    return bloom_array

def get_bloom_table(string_table, match_table):
    bloom_table = {}
    for str_id in match_table:
        rule_id = string_table[str(str_id)]['rid']
        if rule_id not in bloom_table:
            bloom_table[rule_id] = []
        bloom_table[rule_id].append(str_id)
    return bloom_table

def rule_filter (items, bloom_array):
    filtered_rules = {}
    # non_filtered_rules = {}
    for item in items:
        bloom = BloomFilter()
        for pattern in items[item]:
            bloom.add(pattern)
        res = bloom_array.xor(item, bloom)
        if res:
            filtered_rules[item] = res
    return filtered_rules

def main():
    rule_table, string_table, match_table = read_tables()
    bloom_array = build_bloom_filter(rule_table)
    # H_engine = RuleEngine('snort3-community.rules')
    filtered_ids = set()
    non_fitered_ids = set()
    # header_filter = set()
    count = 0
    max = 0
    
    
    for pkt in match_table:
        
        bloom_table = get_bloom_table(string_table, match_table[pkt])
    
        filtered_rules = rule_filter(bloom_table, bloom_array)

        # pkt_hdr = H_engine.extract_hdr(pkt)
        # if pkt_hdr:
        #     matched_rule_ids, matched_rules = H_engine.header_matching(pkt_hdr, filtered_rules)
        #     for r in matched_rule_ids:
        #         header_filter.add(r)

        for rule in bloom_table:
            non_fitered_ids.add(rule_table[str(rule)]["sid"])
        for rule in filtered_rules:
            filtered_ids.add(rule_table[str(rule)]["sid"])
        count += len(filtered_rules)
        if max < len(filtered_rules):
            max = len(filtered_rules)

        # logging.info(f'Respective rule IDs: {bloom_table}')
        # logging.info(f'\nPacket ID: {pkt}')
        # logging.info(f'Matched string IDs: {match_table[pkt]}')
        # matched_strings = ', '.join(str(string_table[str(str_id)]["string"]) for str_id in match_table[pkt])
        # logging.info(f'matched strings: {matched_strings}')    
        # Collect all matched rule IDs into a single string and log it
        # matched_rule_ids = ' '.join(str(rule_table[str(rule_id)]["sid"]) for rule_id in filtered_rules)
        # logging.info(f'Matched rule IDs: {matched_rule_ids}')
    print(f'number of non filtered rules: {len(non_fitered_ids)}')
    # print(f'aleart rule in non filtered rules: {non_fitered_ids.intersection(set([42331, 42340, 42944, 41978]))}')
    print(f'Number of filtered rules: {len(filtered_ids)}')
    # print(f'aleart rule in filtered rules: {filtered_ids.intersection(set([42331, 42340, 42944, 41978]))}')
    print(f'filtered rules: {filtered_ids}')
    matched_rule_ids = ', '.join(str(rule_id) for rule_id in filtered_ids)
    logging.info(f'[{matched_rule_ids}]')
    

    print("\nper packer analysis")
    print(f'Average number of rules matched: {count/len(match_table)}')
    print(f'Maximum number of rules matched: {max}')

    # header_filter = H_engine.matching(filtered_rules)

    # print('\nAfter header match')
    # print(f'Number of filtered rules: {len(filtered_ids.intersection(header_filter))}')

if __name__ == "__main__":
    main()

