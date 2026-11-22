# database.py - everything related to saving and reading incidents from the SQLite database

import math  # math.ceil helps us calculate the number of table pages
import os  # os lets us read the size of the database file
import sqlite3  # built-in library for SQLite databases (no installation needed)
import threading  # a lock keeps the cache safe if two requests arrive at the same time

import pandas as pd  # pandas turns database rows into a DataFrame (a table) for analytics

from config import DATABASE_PATH, SEVERITY_ORDER  # settings from config.py

# ---- Simple cache --------------------------------------------------------
# Several API endpoints need the full table. Instead of re-reading SQLite every time,
# we keep the DataFrame in memory and only reload it when the data has changed.
_cache = {"version": -1, "df": None}  # the saved DataFrame and the data version it belongs to
_state = {"version": 0}  # increases by 1 every time data is inserted or deleted
_lock = threading.Lock()  # makes sure only one request rebuilds the cache at a time


def _bump_version():  # called after any change so the cache knows it is outdated
    _state["version"] += 1  # a new version number invalidates the old cache


def get_connection():  # helper that opens a connection to the database file
    conn = sqlite3.connect(DATABASE_PATH)  # open (or create) the database file
    conn.row_factory = sqlite3.Row  # lets us read columns by name, e.g. row["severity"]
    return conn  # hand the open connection back


def init_db():  # creates the 'incidents' table the first time the app runs
    conn = get_connection()  # open a connection
    conn.execute(  # run one SQL command
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- unique number given automatically
            timestamp TEXT NOT NULL,               -- when it happened
            source_ip TEXT,                        -- the attacker IP
            destination_ip TEXT,                   -- the targeted IP
            attack_type TEXT,                      -- category such as Brute Force
            severity TEXT,                         -- Critical, High, Medium or Low
            status TEXT,                           -- Open, Blocked, Resolved ...
            description TEXT,                      -- human-readable detail
            source_file TEXT                       -- which uploaded file it came from
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(timestamp)")  # faster time sorting
    conn.commit()  # save the changes
    conn.close()  # always close connections when finished


def clear_incidents():  # deletes every incident
    conn = get_connection()  # open a connection
    conn.execute("DELETE FROM incidents")  # remove all rows
    conn.commit()  # save the deletion
    conn.close()  # close the connection
    _bump_version()  # tell the cache its data is now outdated


def insert_incidents(records, source_file):  # saves a list of cleaned incident dictionaries
    rows = [  # build one tuple per incident, in the column order used below
        (r["timestamp"], r["source_ip"], r["destination_ip"], r["attack_type"],
         r["severity"], r["status"], r["description"], source_file)
        for r in records
    ]
    conn = get_connection()  # open a connection
    conn.executemany(  # insert many rows with one command (much faster than a loop)
        """
        INSERT INTO incidents
            (timestamp, source_ip, destination_ip, attack_type, severity, status, description, source_file)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,  # each ? is a safe placeholder (prevents SQL injection)
        rows,
    )
    conn.commit()  # save all inserted rows
    conn.close()  # close the connection
    _bump_version()  # tell the cache its data is now outdated
    return len(rows)  # how many rows were saved


def load_dataframe():  # loads ALL incidents into a pandas DataFrame for the analytics engine
    with _lock:  # only one request at a time may check or rebuild the cache
        if _cache["df"] is not None and _cache["version"] == _state["version"]:  # cache is still fresh
            return _cache["df"]  # reuse it (analytics functions only READ it, never change it)
        conn = get_connection()  # otherwise open a connection
        df = pd.read_sql_query("SELECT * FROM incidents", conn)  # read the whole table
        conn.close()  # close the connection
        df["timestamp"] = pd.to_datetime(df["timestamp"])  # text timestamps -> real datetimes
        _cache["df"] = df  # save it in the cache
        _cache["version"] = _state["version"]  # remember which data version it matches
        return df  # give the DataFrame back


def query_incidents(search="", severity="", attack_type="", page=1, per_page=10, alerts_only=False):
    conditions = []  # list of SQL conditions (filters) we will combine
    params = []  # values for the ? placeholders, in the same order

    if alerts_only:  # the Alerts view only wants Critical and High incidents
        conditions.append("severity IN ('Critical', 'High')")  # fixed text, no user input, so it is safe

    if search:  # if the user typed something in a search box
        conditions.append(
            "(source_ip LIKE ? OR destination_ip LIKE ? OR attack_type LIKE ? "
            "OR description LIKE ? OR status LIKE ?)"
        )
        like = f"%{search}%"  # % means 'anything before/after', so partial text matches
        params.extend([like] * 5)  # one value for each of the 5 placeholders

    if severity:  # exact severity filter
        conditions.append("severity = ?")
        params.append(severity)

    if attack_type:  # exact attack type filter
        conditions.append("attack_type = ?")
        params.append(attack_type)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""  # join all filters, or use nothing

    conn = get_connection()  # open a connection
    total = conn.execute(f"SELECT COUNT(*) FROM incidents {where}", params).fetchone()[0]  # rows that match
    pages = max(1, math.ceil(total / per_page))  # total pages, at least 1
    page = min(max(1, page), pages)  # keep the page number valid
    offset = (page - 1) * per_page  # how many rows to skip

    cursor = conn.execute(
        f"""
        SELECT id, timestamp, source_ip, destination_ip, attack_type, severity, status, description
        FROM incidents {where}
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
        """,  # newest first; LIMIT/OFFSET implement pagination
        params + [per_page, offset],
    )
    items = [dict(row) for row in cursor.fetchall()]  # rows -> normal dictionaries
    conn.close()  # close the connection
    return {"items": items, "total": total, "page": page, "per_page": per_page, "pages": pages}


def get_filter_options():  # values for the filter dropdowns
    conn = get_connection()
    types = [r[0] for r in conn.execute("SELECT DISTINCT attack_type FROM incidents ORDER BY attack_type").fetchall()]
    present = {r[0] for r in conn.execute("SELECT DISTINCT severity FROM incidents").fetchall()}
    conn.close()
    severities = [s for s in SEVERITY_ORDER if s in present]  # keep Critical -> Low order
    return {"attack_types": types, "severities": severities}


def get_stats():  # numbers for the 'Upload & Data' view
    conn = get_connection()  # open a connection
    summary = conn.execute(
        """
        SELECT COUNT(*) AS total,
               MIN(timestamp) AS first_event,
               MAX(timestamp) AS last_event,
               COUNT(DISTINCT CASE WHEN source_ip != 'Unknown' THEN source_ip END) AS unique_ips,
               COUNT(DISTINCT attack_type) AS attack_types
        FROM incidents
        """
    ).fetchone()  # one summary row
    files = [  # how many rows came from each uploaded file
        dict(r) for r in conn.execute(
            "SELECT source_file AS name, COUNT(*) AS row_count FROM incidents "
            "GROUP BY source_file ORDER BY row_count DESC"
        ).fetchall()
    ]
    conn.close()
    size_kb = round(os.path.getsize(DATABASE_PATH) / 1024, 1) if os.path.exists(DATABASE_PATH) else 0  # file size
    return {
        "total": summary["total"],
        "unique_ips": summary["unique_ips"],
        "attack_types": summary["attack_types"],
        "first_event": summary["first_event"],
        "last_event": summary["last_event"],
        "db_size_kb": size_kb,
        "files": files,
    }