# config.py - central place for all project settings (so we never hard-code them in other files)

import os  # os lets us build file paths that work on Windows, Mac and Linux

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # full path of the 'backend' folder (where this file lives)

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")  # folder where raw uploaded log files will be saved

DATABASE_PATH = os.path.join(BASE_DIR, "incidents.db")  # the single file that is our SQLite database

FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))  # path to the 'frontend' folder (one level up)

ALLOWED_EXTENSIONS = {"csv", "json", "log", "txt"}  # only these file types may be uploaded (a basic security check)

MAX_UPLOAD_MB = 20  # biggest file we accept, in megabytes

MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024  # the same limit converted to bytes, which Flask expects

DEFAULT_PAGE_SIZE = 10  # how many table rows to show per page if the browser does not ask for a number

MAX_PAGE_SIZE = 100  # the most rows per page we will ever return (protects the server from huge requests)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]  # the standard order of severity levels, most serious first