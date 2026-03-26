#!/usr/bin/env python3
"""
backend.py — HTTPS/SSL Certificate Audit Tool + Local API Server
=================================================================
Combines the site scanning logic (formerly certs.py) with the Flask
local API server (formerly servidor.py) into a single script.

Usage:
    python backend.py

Dependencies:
    pip install flask flask-cors requests cryptography

Reports are saved to: ./reports/
"""

# ── Dependency check ────────────────────────────────────────────────────────
import sys
import importlib
import importlib.util   # must be imported explicitly on Python 3.14+

REQUIRED = {
    "flask":        "flask",
    "flask_cors":   "flask-cors",
    "requests":     "requests",
    "cryptography": "cryptography",
}

missing = []
for module, package in REQUIRED.items():
    try:
        spec = importlib.util.find_spec(module)
        if spec is None:
            missing.append(package)
    except (ModuleNotFoundError, ValueError):
        missing.append(package)

if missing:
    print("\n" + "=" * 60)
    print("  ERROR: Missing required Python packages.")
    print("=" * 60)
    print("  Please install them with the following command:\n")
    print(f"  pip install {' '.join(missing)}\n")
    print("  Then run this script again.")
    print("=" * 60 + "\n")
    sys.exit(1)

# ── Standard library imports ─────────────────────────────────────────────────
import csv
import http.client
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import queue
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict

# ── Third-party imports ───────────────────────────────────────────────────────
import requests as req_lib
from cryptography import x509
from cryptography import __version__ as crypto_version
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from flask import Flask, request, jsonify, send_file, Response, stream_with_context
from flask_cors import CORS
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── cryptography >= 42 compatibility ─────────────────────────────────────────
_CRYPTO_MAJOR = int(crypto_version.split(".")[0])
USE_UTC_FIELDS = _CRYPTO_MAJOR >= 42

# ── ANSI colors (terminal output only) ───────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok_str(msg):   return f"{GREEN}  \u2714  {msg}{RESET}"
def fail_str(msg): return f"{RED}  \u2718  {msg}{RESET}"

# ── Reports directory ─────────────────────────────────────────────────────────
REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)
PORT = 5151

# ── Active scan tracking for SSE streaming ────────────────────────────────────
# Maps scan_id -> Queue of log lines
_scan_queues: Dict[str, queue.Queue] = {}
_scan_lock = threading.Lock()


# ════════════════════════════════════════════════════════════════════════════
#  SCANNING LOGIC
# ════════════════════════════════════════════════════════════════════════════

def is_ip(host: str) -> bool:
    """Return True if the host string is an IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_entry(raw: str) -> dict:
    """
    Parse a raw site entry into a dict with keys:
    original, host, port, path.
    Accepts formats: domain.com, https://domain.com, domain.com:8443, etc.
    """
    original = raw.strip()
    entry = raw.strip()

    # Normalize scheme
    if entry.lower().startswith("https://"):
        entry = entry[8:]
    elif entry.lower().startswith("http://"):
        entry = entry[7:]

    # Split host+port from path
    if "/" in entry:
        host_port, path = entry.split("/", 1)
        path = "/" + path
    else:
        host_port = entry
        path = ""

    # Split host from port (safe for IPv6 brackets)
    if ":" in host_port:
        parts = host_port.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            host = host_port
            port = 443
    else:
        host = host_port
        port = 443

    return {
        "original": original,
        "host": host,
        "port": port,
        "path": path if path else "/",
    }


def tcp_check(host: str, port: int, timeout: int = 5) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_ssl_cert_info(host: str, port: int, timeout: int = 10) -> dict:
    """
    Perform a TLS handshake and extract certificate information.
    Returns a dict with SSL/TLS details. Returns empty fields on failure.
    Certificate validation is intentionally disabled to capture data
    even from invalid/expired certificates.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result = {
        "ssl_issuer": "",
        "ssl_common_name": "",
        "ssl_valid_from": "",
        "ssl_valid_until": "",
        "ssl_key_algorithm": "",
        "ssl_key_size_bits": "",
        "ssl_cipher_suite": "",
        "tls_version": "",
    }

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # TLS negotiated info
                cipher = ssock.cipher()
                result["ssl_cipher_suite"] = cipher[0] if cipher else ""
                result["tls_version"] = ssock.version() or ""

                # Parse certificate (DER → cryptography object)
                der = ssock.getpeercert(binary_form=True)
                if der:
                    cert = x509.load_der_x509_certificate(der)

                    # Issuer (Issued By)
                    try:
                        result["ssl_issuer"] = cert.issuer.get_attributes_for_oid(
                            x509.NameOID.COMMON_NAME
                        )[0].value
                    except Exception:
                        result["ssl_issuer"] = str(cert.issuer)

                    # Subject Common Name (Issued To)
                    try:
                        result["ssl_common_name"] = cert.subject.get_attributes_for_oid(
                            x509.NameOID.COMMON_NAME
                        )[0].value
                    except Exception:
                        result["ssl_common_name"] = str(cert.subject)

                    # Validity dates
                    if USE_UTC_FIELDS:
                        nb = cert.not_valid_before_utc
                        na = cert.not_valid_after_utc
                    else:
                        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
                        na = cert.not_valid_after.replace(tzinfo=timezone.utc)

                    result["ssl_valid_from"]  = nb.strftime("%Y-%m-%d")
                    result["ssl_valid_until"] = na.strftime("%Y-%m-%d")

                    # Public key algorithm and size
                    pub = cert.public_key()
                    if isinstance(pub, rsa.RSAPublicKey):
                        result["ssl_key_algorithm"] = "RSA"
                        result["ssl_key_size_bits"] = str(pub.key_size)
                    elif isinstance(pub, ec.EllipticCurvePublicKey):
                        result["ssl_key_algorithm"] = "EC"
                        result["ssl_key_size_bits"] = str(pub.key_size)
                    elif isinstance(pub, dsa.DSAPublicKey):
                        result["ssl_key_algorithm"] = "DSA"
                        result["ssl_key_size_bits"] = str(pub.key_size)
                    elif isinstance(pub, ed25519.Ed25519PublicKey):
                        result["ssl_key_algorithm"] = "Ed25519"
                        result["ssl_key_size_bits"] = "256"
                    elif isinstance(pub, ed448.Ed448PublicKey):
                        result["ssl_key_algorithm"] = "Ed448"
                        result["ssl_key_size_bits"] = "448"
                    else:
                        result["ssl_key_algorithm"] = type(pub).__name__
                        result["ssl_key_size_bits"] = ""
    except Exception:
        pass  # Return dict with empty fields

    return result


# Error classification map
_ERROR_MAP = {
    "Name or service not known": "DNS_ERROR",
    "Temporary failure in name resolution": "DNS_ERROR",
    "nodename nor servname provided": "DNS_ERROR",
    "getaddrinfo failed": "DNS_ERROR",
    "timed out": "TIMEOUT",
    "Connection refused": "CONNECTION_REFUSED",
    "Connection reset": "CONNECTION_RESET",
    "SSL": "SSL_ERROR",
    "certificate": "SSL_ERROR",
}


def classify_error(exc: Exception, host_is_ip: bool) -> str:
    """Map an exception message to a standardized error label."""
    msg = str(exc)
    for key, label in _ERROR_MAP.items():
        if key.lower() in msg.lower():
            if label == "DNS_ERROR" and host_is_ip:
                return "UNKNOWN"
            return label
    return "UNKNOWN"


def https_check(host: str, port: int, path: str, host_is_ip: bool, timeout: int = 10):
    """
    Perform an HTTPS GET request.
    Returns tuple: (https_active, error_type, http_code, response_text)
    SSL verification is disabled intentionally to report even invalid certs.
    """
    scheme_host = f"{host}:{port}" if port != 443 else host
    url = f"https://{scheme_host}{path}"

    try:
        resp = req_lib.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        code = resp.status_code
        reason = (resp.reason or "").strip()
        if not reason:
            reason = http.client.responses.get(code, "")
        return True, "", code, reason

    except req_lib.exceptions.ConnectionError as exc:
        return False, classify_error(exc, host_is_ip), "", ""
    except req_lib.exceptions.Timeout:
        return False, "TIMEOUT", "", ""
    except req_lib.exceptions.SSLError:
        return False, "SSL_ERROR", "", ""
    except Exception as exc:
        return False, classify_error(exc, host_is_ip), "", ""


def process_entry(
    idx: int,
    total: int,
    entry: dict,
    log_queue: Optional[queue.Queue] = None,
) -> dict:
    """
    Run all checks for a single site entry and return a result row dict.
    If log_queue is provided, progress lines are sent there for SSE streaming.
    """
    host       = entry["host"]
    port       = entry["port"]
    path       = entry["path"]
    original   = entry["original"]
    host_is_ip = is_ip(host)

    width = len(str(total))
    prefix = f"[{idx:{width}}/{total}]"

    def emit(line: str, console: bool = True):
        """Send a log line to the queue and optionally to console."""
        if log_queue is not None:
            log_queue.put(line)
        if console:
            print(line)

    emit(f"\n{BOLD}{prefix}  {original}{RESET}")

    row = {
        "hostname":          original,
        "https_active":      "",
        "error_type":        "",
        "https_status_code": "",
        "https_status_text": "",
        "ssl_issuer":        "",
        "ssl_common_name":   "",
        "ssl_valid_from":    "",
        "ssl_valid_until":   "",
        "ssl_key_algorithm": "",
        "ssl_key_size_bits": "",
        "ssl_cipher_suite":  "",
        "tls_version":       "",
    }

    # ── TCP check ────────────────────────────────────────────────────────────
    tcp_ok = tcp_check(host, port)
    if tcp_ok:
        emit(f"        {ok_str(f'TCP   port {port} → open')}")
    else:
        emit(f"        {fail_str(f'TCP   port {port} → closed/unreachable')}")
        row["https_active"] = "FALSE"
        row["error_type"]   = "CONNECTION_REFUSED"
        return row

    # ── TLS handshake + certificate ──────────────────────────────────────────
    ssl_info = get_ssl_cert_info(host, port)
    tls_ver  = ssl_info.get("tls_version", "")
    cipher   = ssl_info.get("ssl_cipher_suite", "")

    if tls_ver:
        emit(f"        {ok_str(f'TLS   handshake OK  [{tls_ver}  {cipher}]')}")
        cn     = ssl_info.get("ssl_common_name", "")
        issuer = ssl_info.get("ssl_issuer", "")
        since  = ssl_info.get("ssl_valid_from", "")
        until  = ssl_info.get("ssl_valid_until", "")
        algo   = ssl_info.get("ssl_key_algorithm", "")
        bits   = ssl_info.get("ssl_key_size_bits", "")
        cert_line = f"CN={cn}  Issuer={issuer}  Valid={since} / {until}  {algo} {bits} bits"
        emit(f"        {ok_str(f'CERT  {cert_line}')}")
    else:
        emit(f"        {fail_str('TLS   handshake failed')}")

    # ── HTTPS request ────────────────────────────────────────────────────────
    https_active, error_type, https_code, https_text = https_check(
        host, port, path, host_is_ip
    )

    if https_active:
        emit(f"        {ok_str(f'HTTP  -> {https_code} {https_text}')}")
        row["https_active"]      = "TRUE"
        row["https_status_code"] = https_code
        row["https_status_text"] = https_text
        if tls_ver:
            row.update(ssl_info)
    else:
        emit(f"        {fail_str(f'HTTP  -> {error_type}')}")
        row["https_active"] = "FALSE"
        row["error_type"]   = error_type

    return row


CSV_FIELDNAMES = [
    "hostname", "https_active", "error_type", "https_status_code",
    "https_status_text", "ssl_issuer", "ssl_common_name",
    "ssl_valid_from", "ssl_valid_until", "ssl_key_algorithm",
    "ssl_key_size_bits", "ssl_cipher_suite", "tls_version",
]


def run_scan_in_thread(
    sites_raw: List[str],
    scan_id: str,
    log_q: queue.Queue,
) -> None:
    """
    Run the full site scan in a background thread.
    Results and progress are pushed onto log_q as JSON-encoded SSE lines.
    """
    total   = len(sites_raw)
    entries = [parse_entry(s) for s in sites_raw]
    results = []

    ts           = datetime.now().strftime("%Y%m%d%H%M%S")
    csv_filename = f"report_http_ssl_{ts}.csv"
    csv_path     = REPORTS_DIR / csv_filename

    for idx, entry in enumerate(entries, start=1):
        row = process_entry(idx, total, entry, log_queue=log_q)
        results.append(row)
        # Send structured progress event
        progress_pct = round(idx / total * 100)
        log_q.put(json.dumps({
            "type":    "progress",
            "done":    idx,
            "total":   total,
            "pct":     progress_pct,
            "current": entry["original"],
        }))

    # Ensure reports directory exists (may have been deleted after startup)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Write CSV report
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)

    ok_count   = sum(1 for r in results if r["https_active"] == "TRUE")
    fail_count = total - ok_count

    print(f"\n{'─' * 55}")
    print(f"  {BOLD}Summary:{RESET}  {GREEN}{ok_count} OK{RESET}  /  {RED}{fail_count} FAIL{RESET}  (total: {total})")
    print(f"  Report saved to: {BOLD}{csv_path}{RESET}")
    print(f"{'─' * 55}\n")

    # Send final result event
    csv_content = csv_path.read_text(encoding="utf-8")
    log_q.put(json.dumps({
        "type":         "done",
        "csv":          csv_content,
        "csv_filename": csv_filename,
        "csv_path":     str(csv_path),
        "ok":           ok_count,
        "fail":         fail_count,
        "total":        total,
    }))
    log_q.put(None)  # Sentinel — end of stream


# ════════════════════════════════════════════════════════════════════════════
#  FLASK API ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.route("/ping", methods=["GET"])
def ping():
    """Health-check — lets the dashboard know the backend is running."""
    return jsonify({
        "status":       "ok",
        "python":       sys.executable,
        "reports_dir":  str(REPORTS_DIR),
    })


@app.route("/scan", methods=["POST"])
def start_scan():
    """
    Start a new scan.
    Body (JSON): { "sites": "domain1\\ndomain2\\n..." }
    Returns:     { "scan_id": "<uuid>" }
    The dashboard then opens /stream/<scan_id> as an EventSource.
    """
    import uuid
    data = request.get_json(force=True, silent=True) or {}
    sites_raw = [
        s.strip()
        for s in (data.get("sites") or "").split("\n")
        if s.strip() and not s.strip().startswith("#")
    ]
    if not sites_raw:
        return jsonify({"error": "No sites received."}), 400

    scan_id = str(uuid.uuid4())
    log_q   = queue.Queue()

    with _scan_lock:
        _scan_queues[scan_id] = log_q

    # Run scan in a background thread
    t = threading.Thread(
        target=run_scan_in_thread,
        args=(sites_raw, scan_id, log_q),
        daemon=True,
    )
    t.start()

    return jsonify({"scan_id": scan_id, "total": len(sites_raw)})


@app.route("/stream/<scan_id>", methods=["GET"])
def stream(scan_id: str):
    """
    Server-Sent Events stream for real-time scan progress.
    The client connects to this endpoint as an EventSource.
    Each event is a JSON payload:
      - Log line:   { "type": "log",      "line": "..." }
      - Progress:   { "type": "progress", "done": N, "total": N, "pct": N, "current": "..." }
      - Completion: { "type": "done",     "csv": "...", "csv_filename": "...", ... }
    """
    with _scan_lock:
        log_q = _scan_queues.get(scan_id)
    if log_q is None:
        return jsonify({"error": "Unknown scan ID"}), 404

    def generate():
        try:
            while True:
                item = log_q.get(timeout=300)
                if item is None:
                    # End of stream
                    yield "data: [DONE]\n\n"
                    break
                # Try to parse as structured JSON
                try:
                    parsed = json.loads(item)
                    yield f"data: {json.dumps(parsed)}\n\n"
                except (json.JSONDecodeError, TypeError):
                    # Plain log line
                    yield f"data: {json.dumps({'type': 'log', 'line': str(item)})}\n\n"
        except queue.Empty:
            yield "data: [TIMEOUT]\n\n"
        finally:
            with _scan_lock:
                _scan_queues.pop(scan_id, None)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/reports", methods=["GET"])
def list_reports():
    """List all saved CSV report files in the reports/ directory."""
    files = sorted(
        REPORTS_DIR.glob("report_http_ssl_*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return jsonify([
        {
            "filename": f.name,
            "path":     str(f),
            "size_kb":  round(f.stat().st_size / 1024, 1),
            "modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for f in files
    ])


@app.route("/reports/<filename>", methods=["GET"])
def download_report(filename: str):
    """Download a specific CSV report file."""
    # Security: only allow files in reports dir with .csv extension
    safe_path = REPORTS_DIR / filename
    if (
        not safe_path.exists()
        or safe_path.suffix != ".csv"
        or safe_path.parent.resolve() != REPORTS_DIR.resolve()
    ):
        return jsonify({"error": "File not found."}), 404
    return send_file(str(safe_path), as_attachment=True, download_name=filename)


# ── Legacy /run endpoint (kept for compatibility) ────────────────────────────
@app.route("/run", methods=["POST"])
def run_legacy():
    """
    Legacy synchronous scan endpoint.
    Kept for backward compatibility with older dashboard versions.
    Runs the scan synchronously and returns the full CSV when done.
    """
    data = request.get_json(force=True, silent=True) or {}
    sites_raw = [
        s.strip()
        for s in (data.get("sites") or "").split("\n")
        if s.strip() and not s.strip().startswith("#")
    ]
    if not sites_raw:
        return jsonify({"error": "No sites received."}), 400

    total   = len(sites_raw)
    entries = [parse_entry(s) for s in sites_raw]
    results = []

    stdout_lines = []

    def collect_log(line: str):
        # Strip ANSI codes for clean capture
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        stdout_lines.append(clean)

    log_q = queue.Queue()
    for idx, entry in enumerate(entries, start=1):
        row = process_entry(idx, total, entry, log_queue=log_q)
        results.append(row)
        # Drain queue to stdout_lines
        while not log_q.empty():
            item = log_q.get_nowait()
            if isinstance(item, str):
                import re
                stdout_lines.append(re.sub(r'\x1b\[[0-9;]*m', '', item))

    ts           = datetime.now().strftime("%Y%m%d%H%M%S")
    csv_filename = f"report_http_ssl_{ts}.csv"
    csv_path     = REPORTS_DIR / csv_filename

    # Ensure reports directory exists (may have been deleted after startup)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)

    csv_content = csv_path.read_text(encoding="utf-8")
    return jsonify({
        "status":       "ok",
        "csv":          csv_content,
        "csv_filename": csv_filename,
        "csv_path":     str(csv_path),
        "stdout":       "\n".join(stdout_lines[-3000:]),
        "stderr":       "",
    })


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  🔒  HTTPS/SSL Audit Backend")
    print("=" * 60)
    print(f"  Python     : {sys.executable}")
    print(f"  Reports    : {REPORTS_DIR}")
    print(f"  Server     : http://localhost:{PORT}")
    print("=" * 60)
    print("  Keep this window open while using the dashboard.")
    print("  Press Ctrl+C to stop.\n")

    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
