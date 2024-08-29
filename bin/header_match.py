from scapy.all import *
from scapy.all import IP, TCP
import re
from idstools import rule
import json


class HDREngine:
    def __init__(self, rule_file):
        # Load and preprocess the ruleset
        self.rules_hdr = self.rule_preprocess(rule_file)
        self.hdr_table = self.read_headers()
        self.ip_config = {
            "HOME_NET": 'any',
            "EXTERNAL_NET": 'any',
            "DNS_SERVERS": 'any',
            "FTP_SERVERS": 'any',
            "HTTP_SERVERS": 'any',
            "SIP_SERVERS": 'any',
            "SMTP_SERVERS": 'any',
            "SQL_SERVERS": 'any',
            "SSH_SERVERS": 'any',
            "TELNET_SERVERS": 'any',
            "AIM_SERVERS": [
                "64.12.24.0/23",
                "64.12.28.0/23",
                "64.12.161.0/24",
                "64.12.163.0/24",
                "64.12.200.0/24",
                "205.188.3.0/24",
                "205.188.5.0/24",
                "205.188.7.0/24",
                "205.188.9.0/24",
                "205.188.153.0/24",
                "205.188.179.0/24",
                "205.188.248.0/24"
            ]
        }

        self.port_conf_list = [
            "$FTP_PORTS", "$HTTP_PORTS", "$MAIL_PORTS", "$ORACLE_PORTS",
            "$SIP_PORTS", "$SSH_PORTS", "$FILE_DATA_PORTS"
        ]

        self.port_config = {
            "FTP_PORTS": [21, 2100, 3535],
            "HTTP_PORTS": [
                80, 81, 311, 383, 591, 593, 901, 1220, 1414, 1741, 1830, 2301, 2381, 2809,
                3037, 3128, 3702, 4343, 4848, 5250, 6988, 7000, 7001, 7144, 7145, 7510, 
                7777, 7779, 8000, 8008, 8014, 8028, 8080, 8085, 8088, 8090, 8118, 8123, 
                8180, 8181, 8243, 8280, 8300, 8800, 8888, 8899, 9000, 9060, 9080, 9090, 
                9091, 9443, 9999, 11371, 34443, 34444, 41080, 50002, 55555
            ],
            "MAIL_PORTS": [110, 143],
            "ORACLE_PORTS": list(range(1024, 65536)),
            "SIP_PORTS": [5060, 5061, 5600],
            "SSH_PORTS": [22],
            "FILE_DATA_PORTS": [
                80, 81, 311, 383, 591, 593, 901, 1220, 1414, 1741, 1830, 2301, 2381, 2809,
                3037, 3128, 3702, 4343, 4848, 5250, 6988, 7000, 7001, 7144, 7145, 7510, 
                7777, 7779, 8000, 8008, 8014, 8028, 8080, 8085, 8088, 8090, 8118, 8123, 
                8180, 8181, 8243, 8280, 8300, 8800, 8888, 8899, 9000, 9060, 9080, 9090, 
                9091, 9443, 9999, 11371, 34443, 34444, 41080, 50002, 55555, 110, 143
            ]
        }

    def read_headers(self):
        with open('five_tuples.json', 'r') as hdr_file:
            hdr_table = json.load(hdr_file)
        return hdr_table

    def rule_preprocess(self, rule_file):
        rule_id = 0
        rules_hdr = {}
                        
        for rul in rule.parse_file(rule_file):
            rule_id += 1
            protocol = rul.proto if rul.proto else None
            sip = rul.source_addr if rul.source_addr else None
            dip = rul.dest_addr if rul.dest_addr else None
            sport = rul.source_port if rul.source_port else None
            dport = rul.dest_port if rul.dest_port else None
            
            rules_hdr[rul.sid] = {
                'src_ip': sip,
                'dst_ip': dip,
                'src_port': sport,
                'dst_port': dport,
                'protocol': protocol
            }
            
        return rules_hdr

    def extract_hdr(self, id):
        # Access the FiveTuple from the dictionary using the provided ID
        five_tuple = self.hdr_table[id]
        # print(five_tuple)
        
        if not five_tuple:
            return False  # ID not found in the dictionary

        # Convert IP addresses from integer to dotted decimal format
        src_ip = socket.inet_ntoa(five_tuple['srcAddr'].to_bytes(4, byteorder='big'))
        dst_ip = socket.inet_ntoa(five_tuple['dstAddr'].to_bytes(4, byteorder='big'))
        
        # Map the protocol number to its string representation
        protocol_map = {6: 'tcp', 17: 'udp'}
        proto = protocol_map.get(five_tuple['protocol'], 'unknown')
        
        # Return the extracted header information as a dictionary
        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': five_tuple['srcPort'],
            'dst_port': five_tuple['dstPort'],
            'protocol': proto
        }

    def isList(self, port):
        return '[' in port and ']' in port

    def isRange(self, port):
        return ':' in port
    
    def check_port(self, port, r_port):
        if r_port in self.port_conf_list:
            if port in self.port_config[r_port[1:]]:
                return True
        elif self.isList(r_port):
            if str(port) in r_port:
                return True
        elif self.isRange(r_port):
            if r_port[0] == '!':
                r_port = r_port[1:]
                start, end = r_port.split(':')
                s = int(start) if start else 0
                e = int(end) if end else 65535
                if port not in range(s, e+1):
                    return True
            else:
                start, end = r_port.split(':')
                s = int(start) if start else 0
                e = int(end) if end else 65535
                if port in range(s, e+1):
                    return True
        elif r_port == 'any':
            return True
        else:
            if port == int(r_port):
                return True
        return False

    def check_proto(self, r_proto, p_proto):
        if r_proto == p_proto:
            return True
        elif r_proto == 'ip' and p_proto == 'tcp':
            return True
        return False

    def header_matching(self, pkt_hdr, rule_ids=None):
        if rule_ids is None:
            rule_ids = self.rules_hdr.keys()  # If no rule IDs provided, match all rules
        
        matched_rules = []
        matched_rule_ids = set()  # To keep track of matched rule IDs
        print(f'packet header {pkt_hdr}')
        for rule_id in rule_ids:
#             print(rule_id)
            rule_hdr = self.rules_hdr.get(rule_id)
            print(rule_id,rule_hdr)
            if rule_hdr is None:
                continue  # Skip if rule ID is not found

            # Check if the packet header matches the current rule
            if (self.check_port(pkt_hdr['src_port'], rule_hdr['src_port']) and
                self.check_port(pkt_hdr['dst_port'], rule_hdr['dst_port']) and
                self.check_proto(rule_hdr['protocol'], pkt_hdr['protocol'])):
                
                # Add the rule ID to the set of matched rule IDs
                matched_rule_ids.add(rule_id)
                
                # Add the rule details to the matched_rules list
                matched_rules.append({
                    'id': rule_id,
                    'src_ip': rule_hdr['src_ip'],
                    'dst_ip': rule_hdr['dst_ip'],
                    'src_port': rule_hdr['src_port'],
                    'dst_port': rule_hdr['dst_port'],
                    'protocol': rule_hdr['protocol']
                })

        return matched_rule_ids, matched_rules
