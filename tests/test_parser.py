# test_parser.py - automated tests that prove the log parser works correctly

import os  # for building file paths and deleting temporary files
import sys  # for adding the backend folder to Python's search path
import tempfile  # for creating temporary files that are cleaned up afterwards
import unittest  # Python's built-in testing framework

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))  # path to the backend folder
SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_logs"))  # path to the sample logs folder
sys.path.insert(0, BACKEND_DIR)  # let Python import parser.py from the backend folder

import pandas as pd  # used to build a small table for the column-rename test
from parser import classify_text, parse_file, rename_columns  # the functions we are testing

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}  # the only severity values allowed after cleaning


class ParserTests(unittest.TestCase):  # a group of related tests; each method starting with 'test' is one test

    def write_temp(self, content, suffix):  # helper: writes text into a temporary file and returns its path
        handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8")  # create the temp file
        handle.write(content)  # put the text inside
        handle.close()  # close it so the parser can open it
        self.addCleanup(os.remove, handle.name)  # delete the file automatically when the test ends
        return handle.name  # give the file path back

    def test_classify_sql_injection(self):  # keyword rules should recognise SQL injection
        self.assertEqual(classify_text("payload union select found"), ("SQL Injection", "Critical"))  # expect this exact pair

    def test_classify_default(self):  # unknown text should fall back to the default
        self.assertEqual(classify_text("nothing interesting here"), ("Suspicious Activity", "Low"))  # expect the default pair

    def test_rename_columns(self):  # different column names should become our standard names
        df = pd.DataFrame(columns=["Time", "SRC_IP", "Level"])  # an empty table with unusual column names
        renamed = rename_columns(df)  # run the renaming function
        self.assertIn("timestamp", renamed.columns)  # 'Time' must become 'timestamp'
        self.assertIn("source_ip", renamed.columns)  # 'SRC_IP' must become 'source_ip'
        self.assertIn("severity", renamed.columns)  # 'Level' must become 'severity'

    def test_csv_parsing(self):  # a small CSV should be parsed into clean records
        content = (  # two incident rows plus a header
            "timestamp,source_ip,destination_ip,attack_type,severity,status,description\n"
            "2026-11-14 01:12:45,1.2.3.4,10.0.0.1,Brute Force,high,Blocked,Failed SSH logins\n"
            "2026-11-14 02:00:00,5.6.7.8,10.0.0.2,Malware,CRITICAL,Open,Trojan found\n"
        )
        records, skipped = parse_file(self.write_temp(content, ".csv"))  # parse the temporary CSV
        self.assertEqual(len(records), 2)  # both rows should survive
        self.assertEqual(skipped, 0)  # nothing should be skipped
        self.assertEqual(records[0]["severity"], "High")  # 'high' must be standardised to 'High'
        self.assertEqual(records[1]["severity"], "Critical")  # 'CRITICAL' must become 'Critical'

    def test_bad_timestamp_is_skipped(self):  # rows without a valid time must be dropped and counted
        content = (  # one good row and one row with a nonsense timestamp
            "timestamp,source_ip,attack_type,severity\n"
            "2026-11-14 01:12:45,1.2.3.4,Port Scan,Low\n"
            "not-a-date,5.6.7.8,Port Scan,Low\n"
        )
        records, skipped = parse_file(self.write_temp(content, ".csv"))  # parse it
        self.assertEqual(len(records), 1)  # only the good row remains
        self.assertEqual(skipped, 1)  # exactly one row was skipped

    def test_missing_columns_get_defaults(self):  # columns missing from the file must be filled with safe defaults
        content = "timestamp,description\n2026-11-14 01:12:45,Failed password for root\n"  # only two columns
        records, _skipped = parse_file(self.write_temp(content, ".csv"))  # parse it
        self.assertEqual(records[0]["source_ip"], "Unknown")  # missing IP becomes 'Unknown'
        self.assertEqual(records[0]["status"], "Open")  # missing status becomes 'Open'
        self.assertEqual(records[0]["attack_type"], "Brute Force")  # attack type is guessed from the description

    def test_json_numeric_severity(self):  # numeric levels like 5 must become words
        content = '[{"time": "2026-11-14T05:14:09Z", "src_ip": "1.2.3.4", "event_type": "Malware", "level": 5}]'  # one JSON event
        records, _skipped = parse_file(self.write_temp(content, ".json"))  # parse it
        self.assertEqual(records[0]["severity"], "Critical")  # level 5 means Critical
        self.assertEqual(records[0]["source_ip"], "1.2.3.4")  # 'src_ip' must be recognised as source_ip

    def test_log_line_extraction(self):  # regex extraction from a raw text line
        line = "2026-11-18 02:14:33 sshd: WARNING Failed password for root src=185.220.101.4 dst=10.0.2.15\n"  # raw log line
        records, _skipped = parse_file(self.write_temp(line, ".log"))  # parse it
        self.assertEqual(records[0]["timestamp"], "2026-11-18 02:14:33")  # timestamp found by regex
        self.assertEqual(records[0]["source_ip"], "185.220.101.4")  # first IP is the source
        self.assertEqual(records[0]["destination_ip"], "10.0.2.15")  # second IP is the destination
        self.assertEqual(records[0]["attack_type"], "Brute Force")  # guessed from 'Failed password'
        self.assertEqual(records[0]["severity"], "Medium")  # WARNING maps to Medium

    def test_empty_csv(self):  # a file with only a header row must not crash
        records, skipped = parse_file(self.write_temp("timestamp,source_ip\n", ".csv"))  # parse a header-only file
        self.assertEqual(records, [])  # no records
        self.assertEqual(skipped, 0)  # nothing skipped

    def test_unsupported_extension(self):  # unknown file types must raise a clear error
        with self.assertRaises(ValueError):  # we EXPECT a ValueError here
            parse_file("report.pdf")  # a .pdf is not supported

    def test_all_sample_files(self):  # the three sample logs must parse cleanly
        for name in ["enterprise_security.csv", "firewall_events.json", "server_auth.log"]:  # check each sample file
            path = os.path.join(SAMPLE_DIR, name)  # full path of the sample file
            if not os.path.exists(path):  # if the file is not saved yet
                self.skipTest(f"{name} not found")  # skip instead of failing
            records, skipped = parse_file(path)  # parse the sample file
            self.assertGreaterEqual(len(records), 25, name)  # at least 25 incidents each
            self.assertEqual(skipped, 0, name)  # no rows should be skipped
            for record in records:  # check every single record
                self.assertIn(record["severity"], VALID_SEVERITIES, name)  # severity must be one of the 4 standard levels


if __name__ == "__main__":  # true only when we run this file directly
    unittest.main()  # run all the tests