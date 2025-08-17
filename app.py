import os, json
from flask import Flask, request, jsonify, Response
from db import init_db, insert_request, insert_cert_scan, fetch_all
from cert_utils import analyze_certificate

PORT = int(os.environ.get("PORT", "8080"))
app = Flask(__name__)

with app.app_context():
    init_db()

@app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
def catch_all(path):
    # Skip internal endpoints
    if path in ("logs", "logs.json", "scan-cert", "certs", "certs.json"):
        return Response("Reserved path", status=404)

    body = request.get_data(as_text=True)
    # Trim very large bodies to 1MB
    if body and len(body) > 1_000_000:
        body = body[:1_000_000] + "...(truncated)"
    insert_request(
        ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        method=request.method,
        path="/" + path,
        query_string=request.query_string.decode("utf-8", errors="ignore"),
        headers_dict={k: v for k, v in request.headers.items()},
        body_text=body or ""
    )
    return jsonify({"ok": True, "message": "Request logged"})

@app.get("/logs")
def logs_html():
    rows = fetch_all("requests", limit=200)
    html = ["<h1>Recent HTTP Requests (last 200)</h1><table border=1 cellpadding=6>"]
    if rows:
        html.append("<tr>" + "".join(f"<th>{k}</th>" for k in rows[0].keys()) + "</tr>")
    for r in rows:
        html.append("<tr>" + "".join(f"<td><pre style='white-space:pre-wrap'>{r[k]}</pre></td>" for k in r.keys()) + "</tr>")
    html.append("</table>")
    return Response("\n".join(html), mimetype="text/html")

@app.get("/logs.json")
def logs_json():
    return jsonify(fetch_all("requests", limit=200))

@app.get("/scan-cert")
def scan_cert():
    host = request.args.get("host", "").strip()
    port = int(request.args.get("port", "443"))
    if not host:
        return jsonify({"ok": False, "error": "Missing ?host=example.com"}), 400
    try:
        rec = analyze_certificate(host, port)
        insert_cert_scan(rec)
        # Human-friendly remediation
        remediation = []
        if rec["status"] != "OK":
            remediation.append("Renew or replace the certificate before expiry.")
        if any("SAN" in w for w in rec["warnings"]):
            remediation.append("Re-issue certificate including the hostname in Subject Alternative Name.")
        if any("self-signed" in w for w in rec["warnings"]):
            remediation.append("Use a certificate from a trusted CA for public services.")
        return jsonify({"ok": True, "scan": rec, "remediation": remediation})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/certs")
def certs_html():
    rows = fetch_all("cert_scans", limit=200)
    html = ["<h1>TLS Certificate Scans (last 200)</h1><table border=1 cellpadding=6>"]
    if rows:
        html.append("<tr>" + "".join(f"<th>{k}</th>" for k in rows[0].keys()) + "</tr>")
    for r in rows:
        html.append("<tr>" + "".join(f"<td><pre style='white-space:pre-wrap'>{r[k]}</pre></td>" for k in r.keys()) + "</tr>")
    html.append("</table>")
    return Response("\n".join(html), mimetype="text/html")

@app.get("/certs.json")
def certs_json():
    return jsonify(fetch_all("cert_scans", limit=200))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
