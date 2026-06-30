import httpx
import yaml
import pandas as pd
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import os
from datetime import datetime

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
# Simple Detection Logic
# -----------------------------
def detect_auth(headers, text, url):
    findings = []

    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    text_lower = text.lower()

    # ---------------- Auth Providers ----------------
    if "login.microsoftonline.com" in text_lower or "x-ms-request-id" in headers_lower:
        findings.append(("Microsoft Entra ID", "OIDC"))

    if "okta" in text_lower:
        findings.append(("Okta", "OIDC/SAML"))

    if "auth0" in text_lower:
        findings.append(("Auth0", "OIDC/OAuth2"))

    if "keycloak" in text_lower:
        findings.append(("Keycloak", "OIDC/SAML"))

    # ---------------- Protocols ----------------
    if "saml" in text_lower:
        findings.append(("Unknown", "SAML"))

    if "oauth" in text_lower:
        findings.append(("Unknown", "OAuth2/OIDC"))

    if "bearer" in text_lower:
        findings.append(("Unknown", "Bearer Token"))

    if "basic realm" in text_lower:
        findings.append(("Unknown", "Basic Auth"))

    # ---------------- API / APIM ----------------
    if "ocp-apim-subscription-key" in headers_lower:
        findings.append(("Azure API Management", "API Key"))

    if "apim" in text_lower:
        findings.append(("Azure API Management", "Gateway"))

    # ---------------- WAF Detection ----------------
    if "incapsula" in text_lower or "x-iinfo" in headers_lower:
        findings.append(("Imperva WAF", "WAF"))

    if "azure" in text_lower or "x-azure" in headers_lower:
        findings.append(("Azure WAF/Front Door", "WAF"))

    return findings or [("Unknown", "Unknown")]


# -----------------------------
# Scan Function
# -----------------------------
def scan_domain(url):
    result = {
        "url": url,
        "status": None,
        "provider": "Unknown",
        "protocol": "Unknown",
        "headers": "",
        "title": "",
        "redirect": "",
        "api_gateway": "",
        "waf": "",
    }

    try:
        with httpx.Client(follow_redirects=True, verify=False, timeout=10) as client:
            r = client.get(url)

            result["status"] = r.status_code
            result["headers"] = str(dict(r.headers))
            result["redirect"] = str(r.history)

            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string if soup.title else ""
            result["title"] = title

            findings = detect_auth(dict(r.headers), r.text, url)

            # Pick best match
            provider = findings[0][0]
            protocol = findings[0][1]

            result["provider"] = provider
            result["protocol"] = protocol

            # APIM/WAF tagging
            if "Azure API Management" in provider:
                result["api_gateway"] = "Yes"

            if "Imperva" in provider or "WAF" in provider:
                result["waf"] = "Yes"

    except Exception as e:
        result["status"] = "ERROR"
        result["provider"] = "ERROR"
        result["protocol"] = str(e)

    return result


# -----------------------------
# Run Scanner
# -----------------------------
def run_scan():
    print(f"[AuthRecon] Starting scan of {len(DOMAINS)} domains...")

    results = []

    with ThreadPoolExecutor(max_workers=config["scan"]["threads"]) as executor:
        for res in executor.map(scan_domain, DOMAINS):
            results.append(res)
            print(f"[+] {res['url']} -> {res['provider']} ({res['protocol']})")

    return results


# -----------------------------
# Report Generation
# -----------------------------
def generate_reports(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    df = pd.DataFrame(results)

    excel_path = os.path.join(OUTPUT_DIR, f"AuthRecon_Report_{timestamp}.xlsx")

    df.to_excel(excel_path, index=False)

    html_path = os.path.join(OUTPUT_DIR, f"AuthRecon_Report_{timestamp}.html")

    html = df.to_html(index=False)

    with open(html_path, "w") as f:
        f.write(html)

    print(f"\n[+] Reports generated:")
    print(f"    {excel_path}")
    print(f"    {html_path}")


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    results = run_scan()
    generate_reports(results)