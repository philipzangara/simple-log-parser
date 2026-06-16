# Simple Log Parser - Main entry point
# Accepts a log file, detects the log type, parses it, extracts IOCs, and displays results
# Usage: python parse.py <logfile> [--output json]

import argparse 
import json
from pathlib import Path

from parsers.windows_event import parse_windows_log
from parsers.auth import parse_auth_log
from parsers.apache import parse_apache_log

from log_detector import detect_log_type
from ioc_extractor import extract_iocs

from display import display_results

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Type Log file name")
    parser.add_argument("log", help="Windows Event, apache, or auth logs")
    parser.add_argument("--output", choices=["json"], help="Output format")
    return parser.parse_args(argv)

def main(argv=None) -> None:
    args = parse_args(argv)

    ext = Path(args.log).suffix.lower()
    if ext == ".evtx":
        print("Error: .evtx files are not supported. Export as XML from Event Viewer or use:")
        print("  wevtutil epl <LogName> output.xml /ow:true")
        raise SystemExit(1)
    
    with open(args.log, 'r') as f:
        first_line = f.read(200)
    ioc_type = detect_log_type(first_line)

    if ioc_type == "windows_event":
        result = parse_windows_log(args.log)
    elif ioc_type == "auth_log":
        result = parse_auth_log(args.log)
    elif ioc_type == "apache":
        result = parse_apache_log(args.log)
    else:
        print("Unknown Log type")
        raise SystemExit(1)
    
    iocs = extract_iocs(result, ioc_type)
    
    if args.output == "json":
        print(json.dumps({
            "log_type": ioc_type,
            "event_count": len(result),
            "iocs": iocs
        }, indent=4, default=str))
    else:
        display_results(result, ioc_type, iocs)


if __name__ == "__main__":
    main()