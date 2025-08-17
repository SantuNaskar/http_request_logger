import argparse, os, json, sqlite3, csv
from db import DB_PATH

def export_table(table: str):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(f"SELECT * FROM {table} ORDER BY id ASC")
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", required=True, choices=["requests","cert_scans"])
    ap.add_argument("--format", required=True, choices=["csv","json"])
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = export_table(args.table)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    if args.format == "json":
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    else:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
            else:
                f.write("")
    print(f"Exported {len(rows)} rows to {args.out}")

if __name__ == "__main__":
    main()
