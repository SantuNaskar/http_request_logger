import sys, pathlib, json
from cert_utils import analyze_certificate
from db import insert_cert_scan, init_db

def main():
    if len(sys.argv) != 2:
        print("Usage: python scan_hosts.py hosts.txt")
        sys.exit(1)
    path = pathlib.Path(sys.argv[1])
    if not path.exists():
        print("File not found:", path)
        sys.exit(1)
    init_db()
    count = 0
    for line in path.read_text().splitlines():
        host = line.strip()
        if not host or host.startswith("#"):
            continue
        try:
            rec = analyze_certificate(host, 443)
            insert_cert_scan(rec)
            print("OK:", host, rec["status"], f"{rec['days_to_expiry']}d")
            count += 1
        except Exception as e:
            print("ERR:", host, e)
    print("Scanned:", count)

if __name__ == "__main__":
    main()
