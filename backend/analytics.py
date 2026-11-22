# analytics.py - turns the table of incidents into KPI numbers and chart-ready data

import pandas as pd  # pandas does the grouping and counting

from config import SEVERITY_ORDER  # the fixed order Critical -> Low

SEVERITY_POINTS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}  # risk points per incident, by severity
MAX_TREND_LINES = 8  # draw at most this many separate lines; the rest are merged into 'Other'


def _choose_bucket(df):  # decides whether to group time by hour or by day
    span = df["timestamp"].max() - df["timestamp"].min()  # how long the data covers
    if span <= pd.Timedelta(days=2):  # short data: hourly buckets
        return df["timestamp"].dt.floor("h"), "h", "%d %b %H:%M", "hour"
    return df["timestamp"].dt.floor("D"), "D", "%d %b", "day"  # longer data: daily buckets


def get_sparklines(df, top_type, max_points=24):  # tiny time series used by the KPI card mini-graphs
    bucket, freq, _fmt, _gran = _choose_bucket(df)  # time bucket for every row
    full_range = pd.date_range(bucket.min(), bucket.max(), freq=freq)  # every bucket, even empty ones

    def per_bucket(series):  # helper: fill missing buckets with 0 and keep only the latest points
        return series.reindex(full_range, fill_value=0).tail(max_points)

    known = df["source_ip"] != "Unknown"  # rows that have a real source IP
    series = {
        "total": per_bucket(bucket.value_counts()),  # all incidents per bucket
        "critical": per_bucket(bucket[df["severity"] == "Critical"].value_counts()),  # critical per bucket
        "ips": per_bucket(df[known].groupby(bucket[known])["source_ip"].nunique()),  # distinct IPs per bucket
        "top": per_bucket(bucket[df["attack_type"] == top_type].value_counts()),  # top attack per bucket
    }
    return {name: [int(v) for v in s.values] for name, s in series.items()}  # plain lists for JSON


def get_kpis(df):  # numbers for the four summary cards (plus sidebar badge and sparklines)
    if df.empty:  # no data yet
        return {
            "total_incidents": 0, "critical_alerts": 0, "high_alerts": 0, "alert_count": 0,
            "unique_attacking_ips": 0, "top_attack_type": "N/A", "top_attack_count": 0,
            "spark": {"total": [], "critical": [], "ips": [], "top": []},
        }
    critical = int((df["severity"] == "Critical").sum())  # Critical incidents
    high = int((df["severity"] == "High").sum())  # High incidents
    known_ips = df.loc[df["source_ip"] != "Unknown", "source_ip"]  # source IPs without 'Unknown'
    type_counts = df["attack_type"].value_counts()  # count per attack type, biggest first
    top_type = str(type_counts.index[0])  # name of the most common attack
    return {
        "total_incidents": len(df),
        "critical_alerts": critical,
        "high_alerts": high,
        "alert_count": critical + high,  # shown as the red badge in the sidebar
        "unique_attacking_ips": int(known_ips.nunique()),
        "top_attack_type": top_type,
        "top_attack_count": int(type_counts.iloc[0]),
        "spark": get_sparklines(df, top_type),  # mini-graph data for the KPI cards
    }


def get_trend(df):  # (kept from before) one combined line
    if df.empty:
        return {"granularity": "day", "labels": [], "values": []}
    bucket, freq, label_format, granularity = _choose_bucket(df)
    counts = bucket.value_counts().sort_index()
    counts = counts.reindex(pd.date_range(counts.index.min(), counts.index.max(), freq=freq), fill_value=0)
    return {
        "granularity": granularity,
        "labels": [ts.strftime(label_format) for ts in counts.index],
        "values": [int(v) for v in counts.values],
    }


def get_trend_by_type(df):  # NEW: one line per attack type, all on the same time axis
    if df.empty:  # nothing to plot
        return {"granularity": "day", "labels": [], "datasets": []}
    bucket, freq, label_format, granularity = _choose_bucket(df)  # time bucket for every row
    table = pd.crosstab(bucket, df["attack_type"])  # rows = time buckets, columns = attack types, cells = counts
    full_range = pd.date_range(table.index.min(), table.index.max(), freq=freq)  # every bucket in order
    table = table.reindex(full_range, fill_value=0)  # add empty buckets as 0 so lines are honest
    order = table.sum().sort_values(ascending=False).index.tolist()  # biggest attack types first

    if len(order) > MAX_TREND_LINES + 1:  # too many types would make a messy chart
        keep, rest = order[:MAX_TREND_LINES], order[MAX_TREND_LINES:]  # top types + the leftovers
        datasets = [{"label": str(t), "data": [int(v) for v in table[t].values]} for t in keep]
        datasets.append({"label": "Other", "data": [int(v) for v in table[rest].sum(axis=1).values]})  # merged line
    else:
        datasets = [{"label": str(t), "data": [int(v) for v in table[t].values]} for t in order]

    return {
        "granularity": granularity,  # 'hour' or 'day'
        "labels": [ts.strftime(label_format) for ts in table.index],  # x-axis labels
        "datasets": datasets,  # one entry per line
    }


def get_attack_types(df):  # data for the 'Attack Type Breakdown' doughnut chart
    if df.empty:
        return {"labels": [], "values": []}
    counts = df["attack_type"].value_counts()
    return {"labels": [str(l) for l in counts.index], "values": [int(v) for v in counts.values]}


def get_severity(df):  # data for the severity charts
    counts = df["severity"].value_counts() if not df.empty else pd.Series(dtype=int)
    counts = counts.reindex(SEVERITY_ORDER, fill_value=0)  # force the order Critical -> Low
    return {"labels": SEVERITY_ORDER, "values": [int(v) for v in counts.values]}


def get_top_ips(df, limit=5):  # data for the 'Top Attacking IPs' chart
    if df.empty:
        return {"labels": [], "values": []}
    known = df[df["source_ip"] != "Unknown"]["source_ip"]
    counts = known.value_counts().head(limit)
    return {"labels": [str(l) for l in counts.index], "values": [int(v) for v in counts.values]}


def _risk_level(score):  # converts a 0-100 score into a label
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def get_risk_scores(df, limit=8):  # NEW: risk score (0-100) for the most dangerous source IPs
    known = df[df["source_ip"] != "Unknown"].copy() if not df.empty else df  # ignore unknown IPs
    if known.empty:
        return {"items": []}
    known["points"] = known["severity"].map(SEVERITY_POINTS).fillna(1)  # every incident earns points by severity
    grouped = known.groupby("source_ip")  # one group per IP
    summary = pd.DataFrame({
        "points": grouped["points"].sum(),  # total points per IP
        "incidents": grouped.size(),  # number of incidents per IP
        "critical": grouped["severity"].apply(lambda s: int((s == "Critical").sum())),  # critical count per IP
        "last_seen": grouped["timestamp"].max(),  # most recent event per IP
    }).sort_values("points", ascending=False).head(limit)  # keep only the riskiest IPs

    top_points = float(summary["points"].max()) or 1.0  # the highest total = 100%
    items = []
    for ip, row in summary.iterrows():  # build one result per IP
        score = int(round(100 * float(row["points"]) / top_points))  # relative score 0-100
        favourite = known.loc[known["source_ip"] == ip, "attack_type"].value_counts().index[0]  # its main attack
        items.append({
            "ip": str(ip),
            "score": score,
            "level": _risk_level(score),
            "incidents": int(row["incidents"]),
            "critical": int(row["critical"]),
            "top_attack": str(favourite),
            "last_seen": row["last_seen"].strftime("%Y-%m-%d %H:%M"),
        })
    return {"items": items}