# generate_logs.py - creates a large, realistic, FAKE security log CSV for stress-testing the dashboard

import argparse  # argparse lets us accept options from the terminal, such as --rows 500
import csv  # csv writes properly formatted CSV files (handles commas inside text safely)
import os  # os helps us build a file path that works on every operating system
import random  # random picks attackers, attack types and times
from datetime import datetime, timedelta  # datetime objects let us calculate random timestamps

# Fake external attacker IPs (these are example addresses, not real people)
ATTACKER_IPS = [
    "185.220.101.4", "45.155.205.233", "103.77.192.18", "91.240.118.172", "194.26.29.102",
    "218.92.0.56", "61.177.172.14", "5.188.62.76", "193.32.162.157", "141.98.10.60",
    "77.91.68.10", "89.248.165.52", "162.142.125.9", "198.235.24.130",
]

# Internal company machines that can be targeted or infected
INTERNAL_IPS = ["10.0.1.10", "10.0.1.20", "10.0.2.15", "10.0.3.5", "10.0.4.31", "10.0.4.77"]

# Each attack = (type name, list of possible severities, list of possible descriptions, weight)
# 'weight' controls how common the attack is: a higher number means it appears more often
ATTACKS = [
    ("Brute Force", ["High", "Medium", "Critical"], ["Repeated failed SSH logins", "RDP login threshold exceeded", "Credential stuffing on login page", "VPN account lockout triggered"], 35),
    ("Port Scan", ["Low", "Medium"], ["Sequential scan of ports 1-1024", "Nmap fingerprint detected", "Single probe of web server port"], 25),
    ("SQL Injection", ["Critical", "High"], ["UNION SELECT payload in query string", "OR 1=1 payload in login form", "Blind injection pattern on API"], 12),
    ("Cross-Site Scripting", ["High", "Medium"], ["Script tag injected into form field", "Reflected XSS in search parameter", "Stored XSS payload in comments"], 10),
    ("Phishing", ["High", "Medium"], ["Credential-harvesting email reported", "Suspicious attachment quarantined", "Spoofed executive email detected"], 8),
    ("Malware", ["Critical", "High"], ["Trojan beacon detected on workstation", "Ransomware file encryption activity", "Botnet command and control traffic"], 5),
    ("DDoS", ["Critical", "High"], ["SYN flood against web server", "HTTP flood from botnet nodes", "UDP flood saturating firewall link"], 3),
    ("Privilege Escalation", ["High", "Critical"], ["sudo used to open a root shell", "Unauthorized root access attempt"], 2),
]

# Possible outcomes for the status column
STATUSES = ["Blocked", "Blocked", "Blocked", "Open", "Investigating", "Resolved", "Mitigated"]  # 'Blocked' repeated so it is more common


def make_row(start, days):  # builds ONE fake incident as a list of 7 values
    attack_type, severities, descriptions, _weight = random.choices(  # pick one attack using the weights
        ATTACKS, weights=[a[3] for a in ATTACKS], k=1  # k=1 means pick a single item
    )[0]  # random.choices returns a list, so take its first item
    moment = start + timedelta(seconds=random.randint(0, days * 24 * 3600 - 1))  # random second inside the time window
    source_ip = random.choice(ATTACKER_IPS)  # pick an attacker
    if attack_type in ("Malware", "Privilege Escalation") and random.random() < 0.6:  # these attacks often start inside the network
        source_ip = random.choice(INTERNAL_IPS)  # use an internal machine as the source
    return [  # the 7 CSV columns, in the same order as the header
        moment.strftime("%Y-%m-%d %H:%M:%S"),  # timestamp as text
        source_ip,  # source_ip
        random.choice(INTERNAL_IPS),  # destination_ip
        attack_type,  # attack_type
        random.choice(severities),  # severity
        random.choice(STATUSES),  # status
        random.choice(descriptions),  # description
    ]


def main():  # the main function: reads options, generates rows, writes the file
    parser = argparse.ArgumentParser(description="Generate a fake security log CSV.")  # create the option reader
    parser.add_argument("--rows", type=int, default=500, help="how many incidents to create")  # --rows option, default 500
    parser.add_argument("--days", type=int, default=14, help="how many days the logs should cover")  # --days option, default 14
    parser.add_argument("--seed", type=int, default=42, help="random seed (same seed = same file)")  # --seed option
    args = parser.parse_args()  # read what the user typed in the terminal

    random.seed(args.seed)  # fix the randomness so results are repeatable
    end = datetime(2026, 11, 20)  # the window ends on the project date
    start = end - timedelta(days=args.days)  # the window starts this many days earlier

    rows = [make_row(start, args.days) for _ in range(args.rows)]  # create all the rows
    rows.sort(key=lambda row: row[0])  # sort by timestamp so the file looks like a real chronological log

    folder = os.path.dirname(os.path.abspath(__file__))  # the folder where this script lives (sample_logs)
    out_path = os.path.join(folder, "large_enterprise_logs.csv")  # full path of the output file

    with open(out_path, "w", newline="", encoding="utf-8") as file:  # open the output file for writing
        writer = csv.writer(file)  # create a CSV writer
        writer.writerow(["timestamp", "source_ip", "destination_ip", "attack_type", "severity", "status", "description"])  # header row
        writer.writerows(rows)  # write all incident rows

    print(f"Created {len(rows)} incidents -> {out_path}")  # tell the user where the file is


if __name__ == "__main__":  # true only when we run 'python generate_logs.py' directly
    main()  # start the program