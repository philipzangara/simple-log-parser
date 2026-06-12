import ipaddress
import re
import tldextract

def detect_log_type(first_line: str) -> str:

    if first_line.strip().startswith("<?xml") or "schemas.microsoft.com/win/2004/08/events" in first_line:
        return "windows_event"
    
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    if first_line.split()[0] in months:
        return "auth_log"

    try:
        ipaddress.ip_address(first_line.split()[0])
        return "apache"
    except ValueError:
        return "unknown"


