import os, sqlite3, json, datetime as dt

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "data.sqlite"))

def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    con = _connect()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        ip TEXT,
        method TEXT,
        path TEXT,
        query_string TEXT,
        headers TEXT,
        body TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cert_scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        issuer TEXT,
        subject_cn TEXT,
        san TEXT,
        not_before TEXT,
        not_after TEXT,
        days_to_expiry INTEGER,
        status TEXT,
        warnings TEXT
    )
    """)
    con.commit()
    con.close()

def insert_request(ip, method, path, query_string, headers_dict, body_text):
    con = _connect()
    cur = con.cursor()
    ts = dt.datetime.utcnow().isoformat()
    headers_json = json.dumps(headers_dict, ensure_ascii=False)
    cur.execute("""INSERT INTO requests(ts, ip, method, path, query_string, headers, body)
                   VALUES(?,?,?,?,?,?,?)""",
                (ts, ip, method, path, query_string, headers_json, body_text))
    con.commit()
    con.close()

def insert_cert_scan(rec: dict):
    con = _connect()
    cur = con.cursor()
    ts = dt.datetime.utcnow().isoformat()
    cur.execute("""INSERT INTO cert_scans(ts, host, port, issuer, subject_cn, san, not_before, not_after, days_to_expiry, status, warnings)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, rec.get("host"), rec.get("port", 443), rec.get("issuer"),
                 rec.get("subject_cn"), json.dumps(rec.get("san", []), ensure_ascii=False),
                 rec.get("not_before"), rec.get("not_after"),
                 rec.get("days_to_expiry"), rec.get("status"),
                 json.dumps(rec.get("warnings", []), ensure_ascii=False)))
    con.commit()
    con.close()

def fetch_all(table, limit=200):
    con = _connect()
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows
