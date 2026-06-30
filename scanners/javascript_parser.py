def parse_js_for_auth(evidence: dict):
    """
    Detect authentication frameworks in JavaScript content.
    """

    html = evidence.get("body", "")
    scripts = []

    findings = {
        "msal": False,
        "okta": False,
        "auth0": False,
        "keycloak": False,
        "ping": False,
        "oauth": False,
        "oidc": False,
        "detected_libraries": []
    }

    text = html.lower()

    # ---------------- MSAL (Microsoft Entra ID) ----------------
    if "msal" in text or "msal-browser" in text:
        findings["msal"] = True
        findings["detected_libraries"].append("MSAL")

    # ---------------- Okta ----------------
    if "okta" in text or "okta-auth-js" in text:
        findings["okta"] = True
        findings["detected_libraries"].append("Okta")

    # ---------------- Auth0 ----------------
    if "auth0" in text:
        findings["auth0"] = True
        findings["detected_libraries"].append("Auth0")

    # ---------------- Keycloak ----------------
    if "keycloak" in text:
        findings["keycloak"] = True
        findings["detected_libraries"].append("Keycloak")

    # ---------------- Ping ----------------
    if "ping" in text:
        findings["ping"] = True
        findings["detected_libraries"].append("Ping Identity")

    # ---------------- Protocol hints ----------------
    if "oauth" in text:
        findings["oauth"] = True

    if "oidc" in text or "openid" in text:
        findings["oidc"] = True

    return findings