#!/usr/bin/env python3
"""
SSL / HTTPS Certificate Checker
================================
Connects to a list of web targets and validates:
  1. TCP reachability on the specified (or default 443) port
  2. TLS handshake and full certificate inspection
  3. HTTPS response code and reason phrase

Supported input formats (one entry per line; lines starting with # are ignored):
  IP                        192.168.1.1
  IP/path                   192.168.1.1/api/health
  IP:port                   192.168.1.1:8443
  IP:port/path              192.168.1.1:8443/api/health
  hostname                  example.com
  hostname/path             example.com/login
  hostname:port             example.com:8443
  hostname:port/path        example.com:8443/login
  https://...               any of the above prefixed with https://

Output:  reporte_https_ssl_YYYYMMDDhhmmss.csv  (filename uses local time)

Required third-party packages:
  pip install requests cryptography urllib3
"""

# ─── Dependency check ─────────────────────────────────────────────────────────
# This block runs before any third-party import so that missing packages are
# detected early and the user receives clear installation instructions.

import sys
import subprocess

# Mapping of pip package name → importable module name
_REQUIRED_PACKAGES = {
    "requests":     "requests",
    "cryptography": "cryptography",
    "urllib3":      "urllib3",
}

_missing_packages = []
for _pip_name, _import_name in _REQUIRED_PACKAGES.items():
    try:
        __import__(_import_name)
    except ImportError:
        _missing_packages.append(_pip_name)

if _missing_packages:
    # Detect whether pip3 or pip is the available command on this system
    _pip_available = subprocess.run(
        ["pip3", "--version"], capture_output=True
    ).returncode == 0
    _pip_cmd = "pip3" if _pip_available else "pip"

    print("\n  ERROR: The following required packages are not installed:\n")
    for _pkg in _missing_packages:
        print(f"    \u2022 {_pkg}")

    _pkg_list = " ".join(_missing_packages)
    print("\n  Install them using one of the commands below:\n")
    print(f"    {_pip_cmd} install {_pkg_list}")
    print(
        f"    {_pip_cmd} install {_pkg_list} --break-system-packages"
        "  # Kali Linux / Raspberry Pi OS / Debian externally-managed envs"
    )
    print(
        f"    {_pip_cmd} install {_pkg_list} --user"
        "                   # install for the current user only (no sudo)"
    )
    print(
        f"\n    python3 -m venv .venv && source .venv/bin/activate"
        "  # alternative: use a virtual environment"
    )
    print(f"    pip install {_pkg_list}\n")
    sys.exit(1)

# ─── Standard library imports ─────────────────────────────────────────────────
import csv
import http.client
import ipaddress
import os
import socket
import ssl
from datetime import datetime, timezone

# ─── Third-party imports (safe after the dependency check above) ───────────────
import requests
import urllib3
from cryptography import x509
from cryptography import __version__ as crypto_version
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

# ─── cryptography >= 42 compatibility ─────────────────────────────────────────
# Version 42 deprecated not_valid_before / not_valid_after (naive datetime
# objects) in favour of not_valid_before_utc / not_valid_after_utc (timezone-
# aware datetime objects).  We detect which API to use at import time.
_CRYPTO_MAJOR  = int(crypto_version.split(".")[0])
USE_UTC_FIELDS = _CRYPTO_MAJOR >= 42

# ─── ANSI colour helpers ───────────────────────────────────────────────────────
GREEN = "\033[32m"
RED   = "\033[31m"
RESET = "\033[0m"
BOLD  = "\033[1m"

OK_MARK   = f"{GREEN}\u2714{RESET}"   # ✔ green
FAIL_MARK = f"{RED}\u2718{RESET}"     # ✘ red


def _ok(msg: str) -> str:
    """Return a green check-mark formatted line."""
    return f"{OK_MARK}  {GREEN}{msg}{RESET}"


def _fail(msg: str) -> str:
    """Return a red cross formatted line."""
    return f"{FAIL_MARK}  {RED}{msg}{RESET}"


# ─── Parsing utilities ────────────────────────────────────────────────────────

def is_ip(host: str) -> bool:
    """Return True if *host* is a valid IPv4 or IPv6 literal address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_entry(raw: str) -> dict:
    """
    Parse one line from the input file into its components.

    Returns a dict with:
      original  – the raw string as it appeared in the file
      host      – hostname or IP (without port or path)
      port      – integer port number (defaults to 443 if not specified)
      path      – URL path including leading slash (defaults to '/')

    All supported input formats are handled:
      [https://] [host | IP] [:port] [/path]
    """
    original = raw.strip()
    entry    = raw.strip()

    # Remove the scheme prefix if present
    if entry.lower().startswith("https://"):
        entry = entry[8:]
    elif entry.lower().startswith("http://"):
        entry = entry[7:]

    # Separate the host[:port] part from the /path part
    if "/" in entry:
        host_port, rest = entry.split("/", 1)
        path = "/" + rest
    else:
        host_port = entry
        path      = ""

    # Separate host from :port
    # rsplit on the last colon so that bare IPv6 literals (without brackets)
    # do not cause an incorrect split — they are not supported but will not crash.
    if ":" in host_port:
        parts = host_port.rsplit(":", 1)
        host  = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            # Colon present but the right-hand side is not a valid port number
            host = host_port
            port = 443
    else:
        host = host_port
        port = 443

    return {
        "original": original,
        "host":     host,
        "port":     port,
        "path":     path if path else "/",
    }


# ─── TCP connectivity check ───────────────────────────────────────────────────

def tcp_check(host: str, port: int, timeout: int = 5) -> bool:
    """
    Attempt a raw TCP connection to *host* on *port*.
    Returns True if the connection succeeds, False otherwise.
    No data is sent; the socket is closed immediately after connecting.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ─── TLS handshake + certificate extraction ───────────────────────────────────

def get_ssl_cert_info(host: str, port: int, timeout: int = 10) -> dict:
    """
    Perform a TLS handshake and extract certificate details.

    Certificate extraction uses the *cryptography* library and happens
    entirely at the TLS layer — before any HTTP request is sent.
    SSL verification is intentionally disabled so that certificates can be
    inspected even when they are expired or self-signed.

    Returns a dict with the following string fields (empty on failure):
      ssl_issuer           – Issued By  (CN of the certificate issuer)
      ssl_common_name      – Issued To  (CN of the certificate subject)
      ssl_valid_from       – Not Before date  (YYYY-MM-DD)
      ssl_valid_until      – Not After  date  (YYYY-MM-DD)
      ssl_key_algorithm    – Public key algorithm  (RSA / EC / DSA / Ed25519 / Ed448)
      ssl_key_size_bits    – Public key size in bits
      ssl_cipher_suite     – Cipher suite negotiated during the TLS handshake
      tls_version          – TLS protocol version  (e.g. TLSv1.2, TLSv1.3)
    """
    # Permissive SSL context — we want to read the cert even if it is invalid
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    result = {
        "ssl_issuer":        "",
        "ssl_common_name":   "",
        "ssl_valid_from":    "",
        "ssl_valid_until":   "",
        "ssl_key_algorithm": "",
        "ssl_key_size_bits": "",
        "ssl_cipher_suite":  "",
        "tls_version":       "",
    }

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:

                # ── TLS session metadata ──────────────────────────────────────
                cipher = ssock.cipher()
                result["ssl_cipher_suite"] = cipher[0] if cipher else ""
                result["tls_version"]      = ssock.version() or ""

                # ── Certificate (DER bytes → cryptography object) ─────────────
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return result

                cert = x509.load_der_x509_certificate(der)

                # Issuer Common Name (Issued By)
                try:
                    result["ssl_issuer"] = cert.issuer.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME
                    )[0].value
                except Exception:
                    # Fall back to the full distinguished name string
                    result["ssl_issuer"] = str(cert.issuer)

                # Subject Common Name (Issued To)
                try:
                    result["ssl_common_name"] = cert.subject.get_attributes_for_oid(
                        x509.NameOID.COMMON_NAME
                    )[0].value
                except Exception:
                    result["ssl_common_name"] = str(cert.subject)

                # Validity dates
                # cryptography >= 42 provides timezone-aware UTC datetimes directly;
                # older versions return naive datetimes that we make UTC-aware manually.
                if USE_UTC_FIELDS:
                    not_before = cert.not_valid_before_utc
                    not_after  = cert.not_valid_after_utc
                else:
                    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                    not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

                result["ssl_valid_from"]  = not_before.strftime("%Y-%m-%d")
                result["ssl_valid_until"] = not_after.strftime("%Y-%m-%d")

                # Public key algorithm and key size
                pub = cert.public_key()
                if isinstance(pub, rsa.RSAPublicKey):
                    result["ssl_key_algorithm"] = "RSA"
                    result["ssl_key_size_bits"]  = str(pub.key_size)
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    result["ssl_key_algorithm"] = "EC"
                    result["ssl_key_size_bits"]  = str(pub.key_size)
                elif isinstance(pub, dsa.DSAPublicKey):
                    result["ssl_key_algorithm"] = "DSA"
                    result["ssl_key_size_bits"]  = str(pub.key_size)
                elif isinstance(pub, ed25519.Ed25519PublicKey):
                    result["ssl_key_algorithm"] = "Ed25519"
                    result["ssl_key_size_bits"]  = "256"
                elif isinstance(pub, ed448.Ed448PublicKey):
                    result["ssl_key_algorithm"] = "Ed448"
                    result["ssl_key_size_bits"]  = "448"
                else:
                    # Unknown key type — store the class name as a best effort
                    result["ssl_key_algorithm"] = type(pub).__name__
                    result["ssl_key_size_bits"]  = ""

    except Exception:
        # Any failure (connection error, TLS error, parse error) is silently
        # swallowed and the caller receives a dict with all empty string values.
        pass

    return result


# ─── Error classification ─────────────────────────────────────────────────────

# Substring patterns found in exception messages mapped to error type labels
_ERROR_MAP = {
    "Name or service not known":            "DNS_ERROR",
    "Temporary failure in name resolution": "DNS_ERROR",
    "nodename nor servname provided":       "DNS_ERROR",
    "getaddrinfo failed":                   "DNS_ERROR",
    "timed out":                            "TIMEOUT",
    "Connection refused":                   "CONNECTION_REFUSED",
    "Connection reset":                     "CONNECTION_RESET",
    "SSL":                                  "SSL_ERROR",
    "certificate":                          "SSL_ERROR",
}


def classify_error(exc: Exception, host_is_ip: bool) -> str:
    """
    Map an exception to a short error type label.

    DNS-related errors are reclassified as UNKNOWN when the target host is
    an IP address, because DNS resolution is not performed for IP literals.
    """
    msg = str(exc)
    for substring, label in _ERROR_MAP.items():
        if substring.lower() in msg.lower():
            if label == "DNS_ERROR" and host_is_ip:
                return "UNKNOWN"
            return label
    return "UNKNOWN"


# ─── HTTPS request check ──────────────────────────────────────────────────────

def https_check(
    host: str,
    port: int,
    path: str,
    host_is_ip: bool,
    timeout: int = 10,
) -> tuple:
    """
    Send an HTTPS GET request to the target and return a 4-tuple:
      (https_active, error_type, http_status_code, http_status_text)

    SSL certificate verification is disabled so that sites with invalid
    certificates still produce a measurable HTTP response code.

    The reason phrase returned by requests is normalised with a fallback to
    the standard http.client.responses table to handle servers that omit or
    send an empty reason phrase (e.g. some servers respond 200 with no "OK").
    """
    # Build the request URL; omit the port from the URL when it is the default
    host_part = f"{host}:{port}" if port != 443 else host
    url       = f"https://{host_part}{path}"

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,           # Still report even if the certificate is invalid
            allow_redirects=True,
        )
        status_code = resp.status_code

        # Normalise the reason phrase using http.client as a fallback
        reason = (resp.reason or "").strip()
        if not reason:
            reason = http.client.responses.get(status_code, "")

        return True, "", status_code, reason

    except requests.exceptions.SSLError:
        # SSLError is a subclass of ConnectionError — check it first
        return False, "SSL_ERROR", "", ""
    except requests.exceptions.Timeout:
        return False, "TIMEOUT", "", ""
    except requests.exceptions.ConnectionError as exc:
        return False, classify_error(exc, host_is_ip), "", ""
    except Exception as exc:
        return False, classify_error(exc, host_is_ip), "", ""


# ─── Per-target processor ─────────────────────────────────────────────────────

def process_entry(idx: int, total: int, entry: dict) -> dict:
    """
    Run all validation steps for one target, print a colour-coded progress
    block to stdout, and return a dict ready to be written as a CSV row.

    Steps performed:
      1. TCP connectivity check
      2. TLS handshake + certificate extraction  (skipped if TCP fails)
      3. HTTPS GET request                        (skipped if TCP fails)
    """
    host       = entry["host"]
    port       = entry["port"]
    path       = entry["path"]
    original   = entry["original"]
    host_is_ip = is_ip(host)

    # Progress counter header, e.g.  [ 2/10]  example.com
    width  = len(str(total))
    prefix = f"[{idx:>{width}}/{total}]"
    print(f"\n{BOLD}{prefix}  {original}{RESET}")

    # Initialise the output row — all SSL/HTTP fields default to empty string.
    # Per specification: if HTTPS is not successful, CSV fields remain blank.
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

    # ── Step 1 · TCP connectivity ──────────────────────────────────────────────
    tcp_ok = tcp_check(host, port)
    if tcp_ok:
        print(f"        {_ok(f'TCP   port {port} \u2192 open')}")
    else:
        print(f"        {_fail(f'TCP   port {port} \u2192 closed / unreachable')}")
        row["https_active"] = "FALSE"
        row["error_type"]   = "CONNECTION_REFUSED"
        # Skip TLS and HTTP steps when TCP fails
        return row

    # ── Step 2 · TLS handshake + certificate extraction ───────────────────────
    ssl_info = get_ssl_cert_info(host, port)
    tls_ver  = ssl_info.get("tls_version", "")
    cipher   = ssl_info.get("ssl_cipher_suite", "")

    if tls_ver:
        print(f"        {_ok(f'TLS   handshake OK  [{tls_ver}]')}")

        # Extract all certificate fields into temporary variables to avoid
        # nested f-string quoting issues (SyntaxError in Python < 3.12).
        cn   = ssl_info.get("ssl_common_name", "")
        iss  = ssl_info.get("ssl_issuer", "")
        frm  = ssl_info.get("ssl_valid_from", "")
        til  = ssl_info.get("ssl_valid_until", "")
        algo = ssl_info.get("ssl_key_algorithm", "")
        bits = ssl_info.get("ssl_key_size_bits", "")

        # Line 1 — certificate identity and validity dates
        cert_summary = f"CN={cn}  Issuer={iss}  Valid={frm} / {til}"
        print(f"        {_ok(f'CERT  {cert_summary}')}")

        # Line 2 — public key algorithm and size
        key_summary = f"{algo} {bits} bits"
        print(f"        {_ok(f'KEY   {key_summary}')}")

        # Line 3 — negotiated cipher suite
        print(f"        {_ok(f'CIPH  {cipher}')}")
    else:
        print(f"        {_fail('TLS   handshake failed')}")

    # ── Step 3 · HTTPS request ────────────────────────────────────────────────
    https_active, error_type, status_code, status_text = https_check(
        host, port, path, host_is_ip
    )

    if https_active:
        print(f"        {_ok(f'HTTP  \u2192 {status_code} {status_text}')}")
        row["https_active"]      = "TRUE"
        row["https_status_code"] = status_code
        row["https_status_text"] = status_text
        # Populate SSL fields only when the TLS handshake also succeeded
        if tls_ver:
            row["ssl_issuer"]        = ssl_info.get("ssl_issuer", "")
            row["ssl_common_name"]   = ssl_info.get("ssl_common_name", "")
            row["ssl_valid_from"]    = ssl_info.get("ssl_valid_from", "")
            row["ssl_valid_until"]   = ssl_info.get("ssl_valid_until", "")
            row["ssl_key_algorithm"] = ssl_info.get("ssl_key_algorithm", "")
            row["ssl_key_size_bits"] = ssl_info.get("ssl_key_size_bits", "")
            row["ssl_cipher_suite"]  = ssl_info.get("ssl_cipher_suite", "")
            row["tls_version"]       = ssl_info.get("tls_version", "")
    else:
        print(f"        {_fail(f'HTTP  \u2192 {error_type}')}")
        row["https_active"] = "FALSE"
        row["error_type"]   = error_type

    return row


# ─── File helpers ─────────────────────────────────────────────────────────────

def prompt_for_file() -> str:
    """
    Repeatedly prompt the user for a file path until a valid, existing file
    is provided.  Blank input and non-existent paths both trigger a new prompt.
    """
    while True:
        name = input("Enter the path to the file containing the list of targets: ").strip()
        if not name:
            print(f"{RED}  No filename entered. Please try again.{RESET}")
        elif not os.path.isfile(name):
            print(f"{RED}  File '{name}' not found. Please try again.{RESET}")
        else:
            return name


def read_targets(filepath: str) -> list:
    """
    Read target entries from *filepath*.
    Blank lines and comment lines (starting with '#') are ignored.
    Returns a list of raw entry strings, one per valid line.
    """
    targets = []
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    # Suppress urllib3 InsecureRequestWarning — SSL verification is intentionally
    # disabled to allow reporting on sites with invalid certificates.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"\n{BOLD}SSL / HTTPS Certificate Checker{RESET}")
    print("=" * 55)

    # ── Load target list ──────────────────────────────────────────────────────
    filepath    = prompt_for_file()
    raw_targets = read_targets(filepath)

    if not raw_targets:
        print(f"{RED}  The file is empty or contains no valid entries.{RESET}")
        sys.exit(1)

    total   = len(raw_targets)
    entries = [parse_entry(t) for t in raw_targets]

    print(f"\n  Loaded {BOLD}{total}{RESET} target(s) from '{filepath}'")
    print(f"  cryptography {crypto_version}  |  UTC-aware date fields: {USE_UTC_FIELDS}")

    # ── Prepare the ./reports/ output directory ───────────────────────────────
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    if not os.path.isdir(reports_dir):
        os.makedirs(reports_dir)
        print(f"  Directory created: {BOLD}{reports_dir}{RESET}")
    else:
        print(f"  Output directory:  {BOLD}{reports_dir}{RESET}")

    # ── Prepare the output CSV filename using local time ───────────────────────
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    out_file  = os.path.join(reports_dir, f"report_http_ssl_{timestamp}.csv")

    # CSV column order — matches the spec exactly
    fieldnames = [
        "hostname",
        "https_active",
        "error_type",
        "https_status_code",
        "https_status_text",
        "ssl_issuer",
        "ssl_common_name",
        "ssl_valid_from",
        "ssl_valid_until",
        "ssl_key_algorithm",
        "ssl_key_size_bits",
        "ssl_cipher_suite",
        "tls_version",
    ]

    # ── Run checks for each target ────────────────────────────────────────────
    results = []
    for idx, entry in enumerate(entries, start=1):
        row = process_entry(idx, total, entry)
        results.append(row)

    # ── Write the CSV report ──────────────────────────────────────────────────
    with open(out_file, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    # ── Print final summary ───────────────────────────────────────────────────
    ok_count   = sum(1 for r in results if r["https_active"] == "TRUE")
    fail_count = total - ok_count

    print(f"\n{'─' * 55}")
    print(
        f"  {BOLD}Summary:{RESET}  "
        f"{GREEN}{ok_count} OK{RESET}  /  "
        f"{RED}{fail_count} FAIL{RESET}  "
        f"(total: {total})"
    )
    print(f"  Report saved to: {BOLD}{out_file}{RESET}")
    print(f"{'─' * 55}\n")


if __name__ == "__main__":
    main()
