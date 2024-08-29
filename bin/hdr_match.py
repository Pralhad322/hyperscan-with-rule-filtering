from scapy.all import *
from idstools import rule

class RuleEngine:
    def __init__(self, rule_file):
        # Load and preprocess the ruleset
        self.rules_hdr = self.rule_preprocess(rule_file)
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

    def extract_hdr(self, packet):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto

            if protocol == 6:  # TCP
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    proto = 'tcp'
            elif protocol == 17:  # UDP
                if packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    proto = 'udp'
            elif protocol == 1:  # ICMP
                return False
            else:
                return False
        else:
            return False

        return {'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port, 'protocol': proto}

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

        for rule_id in rule_ids:
#             print(rule_id)
            rule_hdr = self.rules_hdr.get(rule_id)
#             print(rule_id,rule_hdr)
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
    
    def matching(self, filtered_rules):
        header_filter = set()

        packets = rdpcap('pcap/eternalblue.pcap')
        for i, pkt in enumerate(packets):
        #     if i == 10:
        #         break
            pkt_hdr = self.extract_hdr(pkt)
            # print(pkt_hdr)

            if pkt_hdr:
                matched_rule_ids, matched_rules = self.header_matching(pkt_hdr, filtered_rules)
                # print(f'\nMatched Rule IDs (SIDs): {matched_rule_ids}')
                for r in matched_rule_ids:
                    header_filter.add(r)
        return header_filter


# Usage
# rule_file = 'Rules/snort3-community.rules'  # Path to your Snort rule file
# engine = RuleEngine(rule_file)
# # print(engine.rules_hdr)

# header_filter = set()

# packets = rdpcap('pcap/eternalblue.pcap')
# for i, pkt in enumerate(packets):
# #     if i == 10:
# #         break
#     pkt_hdr = engine.extract_hdr(pkt)
#     print(pkt_hdr)

#     if pkt_hdr:
#         matched_rule_ids, matched_rules = engine.header_matching(pkt_hdr, filtered_rules)
#         print(f'\nMatched Rule IDs (SIDs): {matched_rule_ids}')
#         for r in matched_rule_ids:
#             header_filter.add(r)

# print(header_filter)
# print(len(header_filter))