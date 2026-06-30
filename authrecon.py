import httpx
import yaml
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import os
from datetime import datetime

# -----------------------------
# Scanners
# -----------------------------
from scanners.httpx_scanner import run_httpx_scan
from scanners.html_parser import parse_html_for_auth
from scanners.javascript_parser import parse_js_for_auth
from scanners.redirect_parser import parse_redirect_auth

# -----------------------------
# Auth Engine
# -----------------------------
from fingerprints.auth_engine import (
    score_findings,
    classify_login_type
)

# -----------------------------
# Load Config
# -----------------------------
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

OUTPUT_DIR = config["output"]["folder"]
os.makedirs(OUTPUT_DIR, exist_ok=True)

# -----------------------------
# Load Domains
# -----------------------------
with open("domains.txt", "r") as f:
    DOMAINS = [line.strip() for line in f if line.strip()]


# -----------------------------
# WAF Detection
# -----------------------------
def detect_waf(headers, body):
    headers_l = {k.lower(): str(v).lower() for k, v in headers.items()}
    body_l = body.lower()

    waf = None
    confidence = 0
    evidence = []

    # Imperva
    if "visid_incap" in str(headers_l):
        waf = "Imperva"
        confidence += 60
        evidence.append("cookie:visid_incap")

    if "incapsula" in body_l:
        waf = "Imperva"
        confidence += 50
        evidence.append("body:incapsula")

    if "x-iinfo" in headers_l:
        waf = "Imperva"
        confidence += 40
        evidence.append("header:x-iinfo")

    # Azure WAF / Front Door
    if "frontdoor" in body_l or "x-azure" in str(headers_l):
        waf = "Azure WAF / Front Door"
        confidence += 40
        evidence.append("azure_signal")

    if confidence < 50:
        return None, 0, []

    return waf, min(confidence, 100), evidence


# -----------------------------
# Scan Function
# -----------------------------
def scan_domain(url):

    try:
        # 1. HTTP capture
        http_data = run_httpx_scan(url)

        headers = http_data.get("headers", {})
        body = http_data.get("body", "")
        redirect_chain = " ".join(http_data.get("redirect_chain", []))

        # 2. Parsers
        html = parse_html_for_auth(http_data)
        js = parse_js_for_auth(http_data)

        # 3. Redirect analysis
        redirect_signals = parse_redirect_auth(http_data)

        # 4. Auth scoring engine
        auth_result = score_findings(http_data, html, js)

        # 5. Login type classification
        login_result = classify_login_type(body, headers, redirect_chain)

        # 6. WAF detection
        waf, waf_conf, waf_evidence = detect_waf(headers, body)

        # 7. Redirect override (only if stronger signal)
        if redirect_signals:
            best_redirect = max(redirect_signals, key=lambda x: x["confidence"])

            if best_redirect["confidence"] > auth_result["confidence"]:
                auth_result["provider"] = best_redirect["provider"]
                auth_result["protocol"] = best_redirect["protocol"]
                auth_result["confidence"] = best_redirect["confidence"]

        # 8. FINAL RESULT BUILD
        return {
            "url": url,

            # AUTH
            "auth_provider": auth_result["provider"],
            "auth_protocol": auth_result["protocol"],
            "auth_confidence": auth_result["confidence"],

            # LOGIN TYPE
            "login_type": login_result["login_type"],
            "login_confidence": login_result["confidence"],
            "login_evidence": login_result["evidence"],

            # WAF
            "waf": waf,
            "waf_confidence": waf_conf,

            # FULL EVIDENCE
            "evidence": {
                "auth": auth_result.get("scores"),
                "waf": waf_evidence
            }
        }

    except Exception as e:
        return {
            "url": url,
            "auth_provider": "ERROR",
            "auth_protocol": str(e),
            "auth_confidence": 0,
            "login_type": "ERROR",
            "login_confidence": 0
        }


# -----------------------------
# Run Scanner
# -----------------------------
def run_scan():
    print(f"[AuthRecon] Starting scan of {len(DOMAINS)} domains...")

    results = []

    with ThreadPoolExecutor(max_workers=config["scan"]["threads"]) as executor:
        for res in executor.map(scan_domain, DOMAINS):
            results.append(res)

            print(
                f"[+] {res.get('url')} -> "
                f"{res.get('auth_provider')} "
                f"({res.get('auth_protocol')}) | "
                f"{res.get('login_type')}"
            )

    return results


# -----------------------------
# Report Generation
# -----------------------------
def generate_reports(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    df = pd.DataFrame(results)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    excel_path = os.path.join(
        OUTPUT_DIR,
        f"AuthRecon_Report_{timestamp}.xlsx"
    )

    html_path = os.path.join(
        OUTPUT_DIR,
        f"AuthRecon_Report_{timestamp}.html"
    )

    df.to_excel(excel_path, index=False)
    df.to_html(html_path, index=False)

    print("\n[+] Reports generated:")
    print(f"    {excel_path}")
    print(f"    {html_path}")


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    results = run_scan()
    generate_reports(results)