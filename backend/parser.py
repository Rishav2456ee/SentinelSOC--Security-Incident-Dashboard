# parser.py - reads CSV / JSON / .log files and converts them into clean, uniform incident records

import json  # json lets us read .json files
import os  # os helps us find the file extension
import re  # re = regular expressions, used to find timestamps and IPs inside raw text

import pandas as pd  # pandas reads CSV/JSON into tables and cleans columns quickly

# The exact columns every incident must have after cleaning
STANDARD_COLUMNS = [
    "timestamp",  # when it happened
    "source_ip",  # who caused it
    "destination_ip",  # who was targeted
    "attack_type",  # what kind of attack
    "severity",  # how serious
    "status",  # what happened to it
    "description",  # details
]

# Columns that hold plain text (everything except timestamp)
TEXT_COLUMNS = ["source_ip", "destination_ip", "attack_type", "severity", "status", "description"]

# Real-world logs name their columns differently, so we list common alternative names for each standard column
COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "event_time", "eventtime", "@timestamp"],  # time names
    "source_ip": ["source_ip", "src_ip", "srcip", "src", "source", "client_ip", "ip", "source_address"],  # attacker IP names
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "dstip", "dst", "destination", "target_ip"],  # target IP names
    "attack_type": ["attack_type", "event_type", "category", "type", "alert", "signature", "rule", "event"],  # category names
    "severity": ["severity", "level", "priority", "risk", "sev"],  # severity names
    "status": ["status", "action", "outcome", "result"],  # status names
    "description": ["description", "message", "msg", "details", "info"],  # description names
}

# Different tools describe severity in different words; this maps them all to our 4 standard levels
SEVERITY_MAP = {
    "critical": "Critical", "crit": "Critical", "fatal": "Critical", "emergency": "Critical", "5": "Critical",  # most serious
    "high": "High", "error": "High", "major": "High", "4": "High",  # serious
    "medium": "Medium", "med": "Medium", "moderate": "Medium", "warning": "Medium", "warn": "Medium", "3": "Medium",  # moderate
    "low": "Low", "minor": "Low", "info": "Low", "informational": "Low", "notice": "Low", "2": "Low", "1": "Low",  # minor
}

# Keyword rules used to GUESS the attack type (and a default severity) from free text
# Each rule = (keywords to look for, attack type name, default severity)
CLASSIFICATION_RULES = [
    (("sql injection", "union select", "or 1=1"), "SQL Injection", "Critical"),  # attacks on databases
    (("ransomware", "malware", "trojan", "virus", "botnet"), "Malware", "Critical"),  # malicious software
    (("ddos", "syn flood", "flood"), "DDoS", "Critical"),  # traffic flooding
    (("failed password", "authentication failure", "invalid user", "brute"), "Brute Force", "High"),  # password guessing
    (("xss", "<script", "cross-site"), "Cross-Site Scripting", "High"),  # script injection into web pages
    (("phishing", "suspicious email"), "Phishing", "High"),  # fake emails
    (("privilege escalation", "sudo", "unauthorized root"), "Privilege Escalation", "High"),  # gaining higher access
    (("port scan", "portscan", "nmap", "scanning"), "Port Scan", "Medium"),  # probing open ports
]

# Regular expression that finds a timestamp like 2026-11-18 02:14:33 (or with a T between date and time)
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")

# Regular expression that finds an IPv4 address like 185.220.101.4
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Regular expression that finds a log level word such as ERROR or WARNING
LEVEL_PATTERN = re.compile(
    r"\b(CRITICAL|FATAL|HIGH|ERROR|MEDIUM|WARNING|WARN|LOW|INFO|NOTICE)\b", re.IGNORECASE
)


def rename_columns(df):  # makes column names match our standard names
    df.columns = [  # clean every column name
        str(c).strip().lower().replace(" ", "_").replace("-", "_").replace(".", "_")  # lowercase, no spaces/dashes/dots
        for c in df.columns
    ]
    rename_map = {}  # will store 'old name -> standard name'
    for standard, aliases in COLUMN_ALIASES.items():  # go through each standard column
        for alias in aliases:  # try each alternative name in priority order
            if alias in df.columns and alias not in rename_map:  # if the file has it and it is not yet used
                rename_map[alias] = standard  # remember to rename it
                break  # stop at the first match for this standard column
    return df.rename(columns=rename_map)  # apply all renames at once


def classify_text(text):  # guesses (attack_type, severity) from lowercase text
    for keywords, attack_type, severity in CLASSIFICATION_RULES:  # check each rule in order
        if any(word in text for word in keywords):  # if any keyword appears in the text
            return attack_type, severity  # return the first matching rule
    return "Suspicious Activity", "Low"  # default when nothing matches


def enrich_row(row):  # fills gaps in one incident row (called once per row)
    text = (row["attack_type"] + " " + row["description"]).lower()  # combine text fields for keyword search
    guessed_type, guessed_severity = classify_text(text)  # get our best guess

    if row["attack_type"] == "":  # if the file gave no attack type
        row["attack_type"] = guessed_type  # use our guess

    mapped = SEVERITY_MAP.get(row["severity"].lower())  # try to translate the given severity to a standard one
    row["severity"] = mapped if mapped else guessed_severity  # use the translation, or our guess if unknown

    if row["source_ip"] == "":  # if no attacker IP was found
        row["source_ip"] = "Unknown"  # mark it Unknown so counts stay clean
    if row["destination_ip"] == "":  # if no target IP was found
        row["destination_ip"] = "Unknown"  # mark it Unknown
    if row["status"] == "":  # if no status was given
        row["status"] = "Open"  # assume the incident is still open
    if row["description"] == "":  # if no description was given
        row["description"] = row["attack_type"]  # reuse the attack type as the description
    return row  # return the repaired row


def normalize_dataframe(df):  # master cleaning function: raw table in, clean records out
    total_rows = len(df)  # remember how many rows we started with
    if total_rows == 0:  # an empty file has nothing to clean
        return [], 0  # return no records and nothing skipped

    df = rename_columns(df)  # step 1: standardize column names

    for column in STANDARD_COLUMNS:  # step 2: make sure every standard column exists
        if column not in df.columns:  # if the file did not have it
            df[column] = ""  # create it, filled with empty text
    df = df[STANDARD_COLUMNS].copy()  # keep only the standard columns, in a fixed order

    df["timestamp"] = pd.to_datetime(  # step 3: convert text timestamps into real datetimes
        df["timestamp"], errors="coerce", utc=True, format="mixed"  # bad values become NaT; mixed formats allowed
    )
    df["timestamp"] = df["timestamp"].dt.tz_localize(None)  # drop timezone info so all times are comparable
    df = df.dropna(subset=["timestamp"])  # step 4: remove rows whose time could not be understood
    skipped = total_rows - len(df)  # count how many rows we had to throw away

    if df.empty:  # if nothing valid remains
        return [], skipped  # return no records

    for column in TEXT_COLUMNS:  # step 5: clean every text column
        df[column] = df[column].fillna("").astype(str).str.strip()  # empty for missing, text type, no extra spaces
    df["severity"] = df["severity"].str.replace(r"\.0$", "", regex=True)  # turn '5.0' into '5' (numbers from JSON)

    df = df.apply(enrich_row, axis=1)  # step 6: fill gaps and standardize severity, row by row
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")  # step 7: datetime back to a neat text format

    return df.to_dict(orient="records"), skipped  # list of dictionaries + number of skipped rows


def parse_csv(filepath):  # reads a .csv file
    df = pd.read_csv(  # let pandas read the file
        filepath,  # which file
        dtype=str,  # read everything as text so nothing is changed by accident
        keep_default_na=False,  # keep blanks as empty text instead of NaN
        on_bad_lines="skip",  # ignore broken lines instead of crashing
        encoding_errors="replace",  # replace strange characters instead of crashing
    )
    return normalize_dataframe(df)  # clean and return


def parse_json(filepath):  # reads a .json file (also supports one-JSON-object-per-line files)
    with open(filepath, "r", encoding="utf-8", errors="replace") as file:  # open the file safely
        content = file.read()  # read the whole text
    try:  # first, try to read it as one normal JSON document
        data = json.loads(content)  # convert JSON text into Python lists/dicts
    except json.JSONDecodeError:  # if that fails it may be 'JSON Lines' format
        data = [json.loads(line) for line in content.splitlines() if line.strip()]  # parse each non-empty line separately

    if isinstance(data, dict):  # if the top level is an object like {"events": [...]}
        lists = [value for value in data.values() if isinstance(value, list)]  # find any list inside it
        data = lists[0] if lists else [data]  # use that list, or treat the object as a single event

    df = pd.json_normalize(data)  # flatten nested JSON into a flat table
    return normalize_dataframe(df)  # clean and return


def parse_log(filepath):  # reads a plain-text .log file line by line
    rows = []  # will collect one dictionary per log line
    with open(filepath, "r", encoding="utf-8", errors="replace") as file:  # open the file safely
        for line in file:  # go through every line
            line = line.strip()  # remove spaces and newline characters
            if not line:  # skip blank lines
                continue  # move on to the next line
            timestamp = TIMESTAMP_PATTERN.search(line)  # look for a timestamp in the line
            ips = IP_PATTERN.findall(line)  # find every IP address in the line
            level = LEVEL_PATTERN.search(line)  # look for a level word like WARNING
            rows.append(  # store the extracted pieces
                {
                    "timestamp": timestamp.group(0) if timestamp else None,  # the timestamp text, or None
                    "source_ip": ips[0] if len(ips) > 0 else "",  # first IP is treated as the attacker
                    "destination_ip": ips[1] if len(ips) > 1 else "",  # second IP is treated as the target
                    "attack_type": "",  # plain logs have no category; we guess it later from keywords
                    "severity": level.group(1) if level else "",  # the level word, or empty
                    "status": "",  # plain logs have no status
                    "description": line,  # keep the full original line as the description
                }
            )
    return normalize_dataframe(pd.DataFrame(rows))  # clean and return


def parse_file(filepath):  # the single entry point used by the rest of the app
    extension = os.path.splitext(filepath)[1].lower()  # get the extension, e.g. '.csv'
    if extension == ".csv":  # CSV file
        return parse_csv(filepath)  # use the CSV parser
    if extension == ".json":  # JSON file
        return parse_json(filepath)  # use the JSON parser
    if extension in (".log", ".txt"):  # plain text log
        return parse_log(filepath)  # use the line-by-line parser
    raise ValueError(f"Unsupported file type: {extension}")  # anything else is an error