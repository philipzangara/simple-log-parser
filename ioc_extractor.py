# Extracts IOCs from parsed log events using pandas
# Supports: IPs, usernames, hashes, URLs depending on log type
# Input: list of normalized event dicts + log type string
# Output: dict of deduplicated IOC lists

import pandas as pd
import re

def extract_iocs(events: list, log_type: str) -> dict:

    ips: list[str] = []
    usernames: list[str] = []
    hashes: list[str] = []
    urls: list[str] = []

    df = pd.DataFrame(events)
    
    if log_type == "windows_event":
        # EventData fields are nested in the 'data' column
        # Need to expand that dict into columns
        data_df = pd.json_normalize(df["data"].tolist())
        ips = data_df["IpAddress"].dropna().unique().tolist() if "IpAddress" in data_df.columns else []
        usernames = data_df["TargetUserName"].dropna().unique().tolist() if "TargetUserName" in data_df.columns else []
        hashes = data_df["Hashes"].dropna().unique().tolist() if "Hashes" in data_df.columns else []

    elif log_type == "auth_log":
        ip_pattern = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')
        username_pattern = re.compile(r'(?:for|user)\s+(\S+)\s+from')
        ips = df["message"].str.findall(ip_pattern).explode().dropna().unique().tolist()        
        usernames = df["message"].str.findall(username_pattern).explode().dropna().unique().tolist()

    elif log_type == "apache":
        ips = df["ip"].dropna().unique().tolist()
        urls = df["path"].dropna().unique().tolist()

    return {
        "IPs": ips,
        "Usernames": usernames,
        "Hashes": hashes,
        "URLs": urls
    }