# HTTP Request Logger + TLS Certificate Inspector

A complete Python project that:
1. Runs a Flask server and **logs every incoming HTTP request** (method, path, headers, IP, body) into **SQLite**.
2. Provides an endpoint to **inspect SSL/TLS certificates** for any hostname, saving results into SQLite.
3. Exports **CSV/JSON reports** for request logs and certificate scans.
4. Includes a small CLI to bulk-scan hosts from a text file.

---

## Quick Start

### 1) Create & activate a virtual environment (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Run the server
```bash
python app.py
```
Server starts on `http://0.0.0.0:8080` (change PORT with env var).

### 4) Try it
- Open another terminal, send a request:
```bash
curl -X POST "http://127.0.0.1:8080/api/test?foo=bar" -H "X-Demo: 1" -d 'hello'
```
- View recent logs in your browser: `http://127.0.0.1:8080/logs`
- JSON logs API: `http://127.0.0.1:8080/logs.json`

### 5) Run a TLS scan for a host
```bash
curl "http://127.0.0.1:8080/scan-cert?host=www.google.com"
```
- See scan history: `http://127.0.0.1:8080/certs`
- JSON scans API: `http://127.0.0.1:8080/certs.json`

### 6) Export reports
```bash
# All request logs
python3 export_report.py --table requests --format csv --out reports/requests.csv
python3 export_report.py --table requests --format json --out reports/requests.json

# All cert scans
python3 export_report.py --table cert_scans --format csv --out reports/cert_scans.csv
python3 export_report.py --table cert_scans --format json --out reports/cert_scans.json
```

### 7) Bulk TLS scan from a file
Create `hosts.txt` (one host per line), then:
```bash
python3 scan_hosts.py hosts.txt
```

---

## Project Structure

```
http_request_logger_project/
├─ app.py                # Flask app (request logger + TLS scan endpoints + simple UI)
├─ db.py                 # SQLite helpers
├─ cert_utils.py         # TLS certificate fetch & analysis helpers
├─ export_report.py      # Export SQLite tables to CSV/JSON
├─ scan_hosts.py         # CLI: bulk TLS scans from a text file
├─ requirements.txt
├─ hosts.txt             # sample input for bulk scanning
├─ reports/              # exported reports (created when you run exports)
└─ README.md
```

---

## Security & Ethics Notes
- **Only scan hosts you own or have permission to test.** This project fetches public TLS metadata but you must follow your organization's policy and the law.
- Do **not** use this server to capture others' traffic without consent.
- Mask or purge sensitive data when exporting logs.

---

## What gets stored

### `requests` table
- `id` (int, pk)
- `ts` (ISO timestamp, UTC)
- `ip` (string)
- `method` (string)
- `path` (string)
- `query_string` (string)
- `headers` (JSON)
- `body` (string up to 1 MB by default)

### `cert_scans` table
- `id` (int, pk)
- `ts` (ISO timestamp, UTC)
- `host` (string)
- `port` (int)
- `issuer` (string)
- `subject_cn` (string)
- `san` (JSON array)
- `not_before` (ISO time)
- `not_after` (ISO time)
- `days_to_expiry` (int)
- `status` (string: OK | WARNING | CRITICAL)
- `warnings` (JSON array)

---

## License
MIT
