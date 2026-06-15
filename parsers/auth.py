import re

def parse_auth_log(filepath: str) -> list:

    events = []

    # Example: Jun  9 14:23:01 hostname sshd[1234]: Failed password for user from 192.168.1.1 port 22 ssh2
    pattern = re.compile(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)')
    
    with open(filepath, 'r') as f:
        for line in f:
            match = pattern.match(line)
            if match:
                events.append({
                    "month": match.group('month'), 
                    "day": match.group('day'), e 
                    "hostname": match.group('hostname'), 
                    "process": match.group('process'),
                    "message": match.group('message')
        })            

    return events