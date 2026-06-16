# Parses Apache/Nginx access logs into normalized event dicts
# Input: filepath to access log in Combined Log Format
# Output: list of dicts with ip, time, method, path, protocol, status, and size fields

import re

def parse_apache_log(filepath: str) -> list:

    events = []

    # Example: 192.168.1.1 - - [01/Jan/2024:00:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
    pattern = re.compile(r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d\.\d)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)$')
    
    with open(filepath, 'r') as f:
        for line in f:
            match = pattern.match(line)
            if match:
                events.append({
                    "ip": match.group('ip'),
                    "time": match.group('time'),
                    "method": match.group('method'),
                    "path": match.group('path'),
                    "protocol": match.group('protocol'),
                    "status": match.group('status'),
                    "size": match.group('size')
                })            

    return events