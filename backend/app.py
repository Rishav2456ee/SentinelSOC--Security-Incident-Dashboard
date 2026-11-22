# app.py - the main Flask application: starts the server and defines all API endpoints

import os  # for building file paths and creating folders
import time  # for making unique upload file names

from flask import Flask, jsonify, request, send_from_directory  # Flask tools
from werkzeug.utils import secure_filename  # cleans dangerous file names

import analytics  # KPIs and chart data
import config  # our settings
import database  # database helper functions
from parser import parse_file  # log parser entry point

app = Flask(__name__, static_folder=config.FRONTEND_FOLDER, static_url_path="")  # serve frontend files directly
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH  # reject uploads bigger than our limit

os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)  # create the uploads folder if missing
database.init_db()  # create the database table if missing


def allowed_file(filename):  # checks that the uploaded file has an allowed extension
    return "." in filename and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS


@app.route("/")  # the dashboard page
def index():
    return send_from_directory(config.FRONTEND_FOLDER, "index.html")


@app.route("/api/health")  # NEW: the 'Backend Connected' pill calls this every few seconds
def api_health():
    return jsonify({"status": "ok"})  # if the browser gets this reply, the backend is alive


@app.route("/api/upload", methods=["POST"])  # receives a log file
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file was sent."}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file was selected."}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Only .csv, .json, .log and .txt files are allowed."}), 400

    safe_name = secure_filename(file.filename)  # remove dangerous characters from the name
    if not safe_name:
        return jsonify({"error": "Invalid file name."}), 400
    unique_name = f"{int(time.time())}_{safe_name}"  # time prefix so names never collide
    save_path = os.path.join(config.UPLOAD_FOLDER, unique_name)
    file.save(save_path)  # write the file to disk

    try:
        records, skipped = parse_file(save_path)  # parse and clean the file
    except Exception as error:
        return jsonify({"error": f"Could not parse the file: {error}"}), 400

    if not records:
        return jsonify({"error": "No valid incidents found. Check that rows contain a timestamp."}), 400

    mode = request.form.get("mode", "replace")  # 'replace' (default) or 'append'
    if mode == "replace":
        database.clear_incidents()  # start fresh
    inserted = database.insert_incidents(records, safe_name)  # save the new incidents

    return jsonify({
        "message": "File processed successfully.",
        "filename": safe_name,
        "inserted": inserted,
        "skipped": skipped,
        "mode": mode,
    })


@app.route("/api/kpis")  # KPI cards + sidebar badge + sparklines
def api_kpis():
    return jsonify(analytics.get_kpis(database.load_dataframe()))


@app.route("/api/charts/trend")  # (kept) single combined line
def api_trend():
    return jsonify(analytics.get_trend(database.load_dataframe()))


@app.route("/api/charts/trend-by-type")  # NEW: one line per attack type
def api_trend_by_type():
    return jsonify(analytics.get_trend_by_type(database.load_dataframe()))


@app.route("/api/charts/attack-types")  # attack type counts
def api_attack_types():
    return jsonify(analytics.get_attack_types(database.load_dataframe()))


@app.route("/api/charts/severity")  # severity counts
def api_severity():
    return jsonify(analytics.get_severity(database.load_dataframe()))


@app.route("/api/charts/top-ips")  # most active attacker IPs
def api_top_ips():
    return jsonify(analytics.get_top_ips(database.load_dataframe()))


@app.route("/api/risk/ips")  # NEW: risk score per attacker IP
def api_risk_ips():
    limit = request.args.get("limit", 8, type=int)  # how many IPs to return
    limit = min(max(limit, 1), 20)  # keep between 1 and 20
    return jsonify(analytics.get_risk_scores(database.load_dataframe(), limit))


@app.route("/api/stats")  # NEW: database statistics for the Upload & Data view
def api_stats():
    return jsonify(database.get_stats())


@app.route("/api/incidents")  # searchable, filterable table
def api_incidents():
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    attack_type = request.args.get("attack_type", "").strip()
    alerts_only = request.args.get("alerts_only", "").lower() in ("1", "true", "yes")  # NEW: Critical + High only
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", config.DEFAULT_PAGE_SIZE, type=int)
    per_page = min(max(per_page, 1), config.MAX_PAGE_SIZE)
    return jsonify(database.query_incidents(search, severity, attack_type, page, per_page, alerts_only))


@app.route("/api/filters")  # dropdown options
def api_filters():
    return jsonify(database.get_filter_options())


@app.route("/api/incidents", methods=["DELETE"])  # wipe all data
def api_clear():
    database.clear_incidents()
    return jsonify({"message": "All incidents cleared."})


@app.errorhandler(413)  # upload too large
def file_too_large(_error):
    return jsonify({"error": f"File too large. Maximum size is {config.MAX_UPLOAD_MB} MB."}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)  # debug=True auto-restarts when code changes