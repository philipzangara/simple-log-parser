# Handles terminal output formatting for Simple Log Parser
# Prints log summary, event count, and extracted IOCs

from typing import Any

def display_results(results: list, ioc_type: str, iocs: dict) -> None:
    print("=== Simple Log Parser v1.0.0 ===")
    print()
    
    print_field("Log Type:", ioc_type)
    print_field("Events Parsed:", len(results))
    
    print()
    print("=== Extracted IOCs ===")
    print_field("IPs:", ", ".join(iocs.get("IPs", [])) or "None")
    print_field("Usernames:", ", ".join(iocs.get("Usernames", [])) or "None")
    print_field("Hashes:", ", ".join(iocs.get("Hashes", [])) or "None")
    print_field("URLs:", ", ".join(iocs.get("URLs", [])) or "None")
    
def print_field(label: str, value: Any) -> None:
    print(f"{label:<30} {value}")