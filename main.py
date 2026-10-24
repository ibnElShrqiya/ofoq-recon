#!/usr/bin/env python3
"""OFOQ Recon — safe, low-impact web security assessment toolkit."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

try:
    import requests
except ImportError:
    print("Missing dependency: requests. Install with: python -m pip install -r requirements.txt")
    raise SystemExit(2)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    Console = None
    Panel = Table = Text = None

APP_NAME = "OFOQ Recon"
VERSION = "1.0.1"
USER_AGENT = f"OFOQ-Recon/{VERSION} (authorized low-impact security assessment)"
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 20
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 256_000
PRIVATE_NETS = (
    ("10.",), ("127.",), ("169.254.",), ("192.168.",), ("172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31."), ("0.",)
)

console = Console() if Console else None


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    status: str
    detail: str
    recommendation: str


def say(message: str, style: str | None = None) -> None:
    if console:
        console.print(message, style=style)
    else:
        print(message)


def banner() -> None:
    art = r"""
   ____  _____ ____   ___
  / __ \|  ___/ ___| / _ \
 | |  | | |_  \___ \| | | |
 | |__| |  _|  ___) | |_| |
  \____/|_|   |____/ \___/

          OFOQ RECON v1.0.0
    Authorized Web Security Assessment
"""
    if console:
        console.print(Panel(Text(art, style="bold cyan"), border_style="bright_blue"))
    else:
        print(art)


def is_private_or_special_ip(ip: str) -> bool:
    try:
        import ipaddress
        address = ipaddress.ip_address(ip)
        return not address.is_global
    except ValueError:
        return True


def resolve_host(host: str) -> list[str]:
    found = set()
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        found.add(item[4][0])
    return sorted(found)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("URL cannot be empty.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Could not parse a hostname from the URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    host = parsed.hostname.encode("idna").decode("ascii")
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if parsed.port:
        netloc += f":{parsed.port}"
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def guard_url(url: str, allow_private: bool) -> tuple[str, list[str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host.lower() in {"localhost", "localhost.localdomain"} and not allow_private:
        raise ValueError("Local/private targets are blocked by default. Use --allow-private only for systems you own or are authorized to test.")
    try:
        ips = resolve_host(host)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {host}: {exc}") from exc
    if not ips:
        raise ValueError(f"No IP addresses resolved for {host}.")
    if not allow_private and any(is_private_or_special_ip(ip) for ip in ips):
        raise ValueError(
            f"{host} resolves to a private or special-use address ({', '.join(ips)}). "
            "Private targets are blocked by default; use --allow-private only for systems you own or are authorized to test."
        )
    return host, ips


def safe_get(session: requests.Session, url: str, allow_private: bool, headers: dict[str, str] | None = None):
    """GET with explicit redirect handling and target validation at each hop."""
    current = url
    history = []
    for _ in range(MAX_REDIRECTS + 1):
        guard_url(current, allow_private)
        response = session.get(
            current, allow_redirects=False,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True,
            headers=headers or {}, verify=True
        )
        # Redirect bodies are irrelevant; don't let a slow redirect body hide its status.
        if response.is_redirect or response.is_permanent_redirect:
            response._content = b""
            response._content_consumed = True
            response.close()
        else:
            # Read a bounded response body. If the body stalls after headers arrive,
            # keep the HTTP status and headers and report a partial-body warning.
            chunks = []
            total = 0
            body_read_error = None
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    remaining = MAX_BODY_BYTES - total
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    total += min(len(chunk), remaining)
                    if total >= MAX_BODY_BYTES:
                        break
            except requests.exceptions.ReadTimeout as exc:
                body_read_error = f"Response body read timed out after {READ_TIMEOUT}s; partial response retained."
            except requests.exceptions.ChunkedEncodingError as exc:
                body_read_error = f"Response body ended unexpectedly; partial response retained: {exc}"
            finally:
                response._content = b"".join(chunks)
                response._content_consumed = True
                response.close()
            response._ofoq_body_read_error = body_read_error
        history.append({"url": current, "status_code": response.status_code})
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                return response, history
            current = normalize_url(urljoin(current, location))
            continue
        return response, history
    raise ValueError(f"Too many redirects (limit {MAX_REDIRECTS}).")


def tls_info(host: str, port: int = 443) -> dict[str, Any]:
    result: dict[str, Any] = {"checked": False}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                result = {
                    "checked": True,
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
                }
                if cert.get("notAfter"):
                    try:
                        expiry = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
                        days = (expiry - dt.datetime.now(dt.timezone.utc)).days
                        result["days_until_expiry"] = days
                    except ValueError:
                        pass
    except Exception as exc:
        result["error"] = str(exc)
    return result


def add_finding(findings: list[Finding], fid: str, title: str, severity: str, status: str,
                detail: str, recommendation: str) -> None:
    findings.append(Finding(fid, title, severity, status, detail, recommendation))


def inspect_headers(headers: requests.structures.CaseInsensitiveDict, findings: list[Finding]) -> dict[str, Any]:
    header_names = {k.lower(): v for k, v in headers.items()}
    checks = [
        ("content-security-policy", "CSP", "medium",
         "A Content-Security-Policy header was not observed.",
         "Define a CSP suited to the application; start with report-only mode if needed."),
        ("x-content-type-options", "X-Content-Type-Options", "low",
         "X-Content-Type-Options was not observed.",
         "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy", "low",
         "Referrer-Policy was not observed.",
         "Set a suitable policy such as strict-origin-when-cross-origin."),
        ("permissions-policy", "Permissions-Policy", "low",
         "Permissions-Policy was not observed.",
         "Disable browser features the application does not need."),
    ]
    if urlparse("https://" + "example.invalid").scheme == "https" and "strict-transport-security" not in header_names:
        add_finding(findings, "WEB-001", "HSTS header missing", "medium", "potential",
                    "Strict-Transport-Security was not observed in the response headers.",
                    "For HTTPS-only sites, configure HSTS after confirming all relevant subdomains support HTTPS.")
    for key, label, severity, detail, recommendation in checks:
        if key not in header_names:
            add_finding(findings, f"WEB-{len(findings)+1:03d}", f"{label} header missing", severity, "potential",
                        detail, recommendation)
    server = header_names.get("server")
    powered = header_names.get("x-powered-by")
    if server or powered:
        exposed = "; ".join(x for x in [f"Server: {server}" if server else "", f"X-Powered-By: {powered}" if powered else ""] if x)
        add_finding(findings, "INFO-001", "Technology details exposed in headers", "info", "observed",
                    exposed, "Consider reducing unnecessary version and platform disclosure.")
    cors = header_names.get("access-control-allow-origin")
    if cors == "*" and header_names.get("access-control-allow-credentials", "").lower() == "true":
        add_finding(findings, "CORS-001", "Potentially unsafe CORS combination", "high", "potential",
                    "The response appears to combine Access-Control-Allow-Origin: * with credentials=true. Browser behavior and the actual request context should be verified.",
                    "Use an explicit allowlist of trusted origins and never reflect arbitrary origins.")
    elif cors:
        add_finding(findings, "INFO-002", "CORS policy advertised", "info", "observed",
                    f"Access-Control-Allow-Origin: {cors}", "Confirm the allowed origins match the application's intended trust boundary.")
    return {
        "security_headers_present": {key: key in header_names for key, *_ in checks},
        "hsts_present": "strict-transport-security" in header_names,
        "server_header": server,
        "x_powered_by": powered,
        "access_control_allow_origin": cors,
    }


def scan(url: str, allow_private: bool) -> dict[str, Any]:
    started = time.time()
    normalized = normalize_url(url)
    host, ips = guard_url(normalized, allow_private)
    findings: list[Finding] = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    errors: list[str] = []
    response_data: dict[str, Any] = {}
    redirect_history = []
    headers_data: dict[str, Any] = {}

    say(f"[cyan]Target:[/cyan] {normalized}" if console else f"Target: {normalized}")
    say(f"[cyan]Resolved IPs:[/cyan] {', '.join(ips)}" if console else f"Resolved IPs: {', '.join(ips)}")

    try:
        response, redirect_history = safe_get(session, normalized, allow_private)
        final_url = response.url or redirect_history[-1]["url"]
        response_data = {
            "status_code": response.status_code,
            "reason": response.reason,
            "final_url": final_url,
            "content_type": response.headers.get("Content-Type"),
            "content_length_header": response.headers.get("Content-Length"),
            "response_bytes_read": len(response.content),
            "elapsed_seconds": round(time.time() - started, 3),
            "body_read_warning": getattr(response, "_ofoq_body_read_error", None),
        }
        if response_data["body_read_warning"]:
            add_finding(findings, "HTTP-003", "Response body read timed out", "info", "partial",
                        response_data["body_read_warning"] + " HTTP status and headers were still inspected.",
                        "Retry later or increase READ_TIMEOUT if the target is expected to respond slowly.")
        headers_data = inspect_headers(response.headers, findings)
        if response.status_code >= 500:
            add_finding(findings, "HTTP-001", "Server error response", "low", "observed",
                        f"The target returned HTTP {response.status_code}. This may be temporary or expected.",
                        "Review server logs and confirm the response is intended.")
        if urlparse(normalized).scheme == "http":
            add_finding(findings, "TLS-001", "Target uses HTTP", "high", "observed",
                        "The submitted URL uses unencrypted HTTP.",
                        "Redirect to HTTPS and ensure sensitive data is never transmitted over plain HTTP.")
        if redirect_history and len(redirect_history) > 1:
            add_finding(findings, "HTTP-002", "Redirect chain observed", "info", "observed",
                        " -> ".join(f"{x['status_code']} {x['url']}" for x in redirect_history),
                        "Confirm all redirects are expected and terminate at the intended HTTPS hostname.")
    except Exception as exc:
        errors.append(str(exc))
        add_finding(findings, "SCAN-001", "HTTP request could not complete", "info", "inconclusive",
                    str(exc), "Verify DNS, network access, URL correctness, and whether the site requires authentication.")

    parsed = urlparse(normalized)
    tls = {}
    if parsed.scheme == "https":
        port = parsed.port or 443
        tls = tls_info(host, port)
        if tls.get("checked") and tls.get("days_until_expiry") is not None:
            days = tls["days_until_expiry"]
            if days < 0:
                add_finding(findings, "TLS-002", "TLS certificate expired", "high", "observed",
                            f"The certificate appears to have expired {abs(days)} day(s) ago.",
                            "Renew the certificate and verify the full certificate chain.")
            elif days <= 21:
                add_finding(findings, "TLS-003", "TLS certificate nearing expiry", "medium", "observed",
                            f"The certificate expires in {days} day(s).",
                            "Renew the certificate before expiry and automate expiry monitoring.")
        if tls.get("error"):
            add_finding(findings, "TLS-004", "TLS inspection incomplete", "info", "inconclusive",
                        tls["error"], "Confirm the TLS endpoint is reachable and uses a trusted certificate.")
    else:
        tls = {"checked": False, "note": "TLS inspection skipped because the URL uses HTTP."}

    aux: dict[str, Any] = {}
    for path in ("/robots.txt", "/sitemap.xml"):
        check_url = urljoin(normalized, path)
        try:
            r, _ = safe_get(session, check_url, allow_private)
            aux[path] = {"status_code": r.status_code, "content_type": r.headers.get("Content-Type")}
        except Exception as exc:
            aux[path] = {"error": str(exc)}
    if aux.get("/robots.txt", {}).get("status_code") == 200:
        add_finding(findings, "INFO-003", "robots.txt is accessible", "info", "observed",
                    "robots.txt is publicly accessible. Its contents were not interpreted as a security boundary.",
                    "Do not place secrets or access-control rules in robots.txt; it is not an access-control mechanism.")
    if aux.get("/sitemap.xml", {}).get("status_code") == 200:
        add_finding(findings, "INFO-004", "sitemap.xml is accessible", "info", "observed",
                    "A sitemap is publicly accessible, which is common for public websites.",
                    "Ensure the sitemap contains only URLs intended to be public.")

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    counts = {s: sum(1 for f in findings if f.severity == s) for s in severity_rank}
    return {
        "tool": APP_NAME,
        "version": VERSION,
        "scan_timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": normalized,
        "hostname": host,
        "resolved_ips": ips,
        "scope_note": "Low-impact checks only. Findings are indicators, not proof of exploitability. Test only systems you own or are explicitly authorized to assess.",
        "http": response_data,
        "redirect_history": redirect_history,
        "headers": headers_data,
        "tls": tls,
        "well_known_paths": aux,
        "errors": errors,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
            "highest_severity": max((f.severity for f in findings), key=lambda s: severity_rank[s], default="none"),
            "duration_seconds": round(time.time() - started, 3),
        },
        "findings": [asdict(f) for f in findings],
    }


def write_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def write_html(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = report.get("findings", [])
    severity_colors = {
        "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
        "low": "#1d4ed8", "info": "#475569", "none": "#166534"
    }
    rows = []
    for f in findings:
        sev = html.escape(str(f.get("severity", "info")).upper())
        color = severity_colors.get(str(f.get("severity", "info")), "#475569")
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(f.get('id','')))}</code></td>"
            f"<td>{html.escape(str(f.get('title','')))}</td>"
            f"<td><span class='badge' style='background:{color}'>{sev}</span></td>"
            f"<td>{html.escape(str(f.get('status','')))}</td>"
            f"<td>{html.escape(str(f.get('detail','')))}</td>"
            f"<td>{html.escape(str(f.get('recommendation','')))}</td>"
            "</tr>"
        )
    summary = report.get("summary", {})
    counts = summary.get("severity_counts", {})
    count_html = "".join(
        f"<div class='metric'><span>{html.escape(k.title())}</span><strong>{int(v)}</strong></div>"
        for k, v in counts.items()
    )
    http_json = html.escape(json.dumps(report.get("http", {}), indent=2, ensure_ascii=False))
    tls_json = html.escape(json.dumps(report.get("tls", {}), indent=2, ensure_ascii=False))
    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OFOQ Recon Report — {html.escape(report.get('hostname','target'))}</title>
<style>
:root{{--bg:#07111f;--card:#0e1b2d;--line:#22334a;--text:#e5edf7;--muted:#9fb0c5;--cyan:#22d3ee}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,Segoe UI,Arial,sans-serif}}
header{{padding:32px 5vw;backg
