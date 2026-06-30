def score_findings(http_data, html_findings, js_findings):
    """
    Simple scoring engine for authentication classification.
    """

    scores = {}

    def add(provider, points):
        scores[provider] = scores.get(provider, 0) + points

    # -------------------------
    # HTTP / Header Signals
    # -------------------------
    headers = http_data.get("headers", {})
    body = http_data.get("body", "").lower()
    redirect_chain = " ".join(http_data.get("redirect_chain", [])).lower()

    # Entra ID
    if "login.microsoftonline.com" in body or "msal" in body:
        add("Microsoft Entra ID", 50)

    if "x-ms-request-id" in str(headers).lower():
        add("Microsoft Entra ID", 20)

    if "login.microsoftonline.com" in redirect_chain:
        add("Microsoft Entra ID", 40)

    # Okta
    if "okta" in body:
        add("Okta", 50)

    # Auth0
    if "auth0" in body:
        add("Auth0", 50)

    # Keycloak
    if "keycloak" in body:
        add("Keycloak", 50)

    # -------------------------
    # Protocol Signals (HTML)
    # -------------------------
    if html_findings.get("saml_hint"):
        add("SAML", 40)

    if html_findings.get("oidc_hint"):
        add("OIDC", 40)

    if html_findings.get("oauth_hint"):
        add("OAuth2", 30)

    if html_findings.get("login_form"):
        add("Forms-Based Login", 20)

    # -------------------------
    # JS Signals
    # -------------------------
    if js_findings.get("msal"):
        add("Microsoft Entra ID", 40)

    if js_findings.get("okta"):
        add("Okta", 40)

    if js_findings.get("auth0"):
        add("Auth0", 40)

    if js_findings.get("keycloak"):
        add("Keycloak", 40)

    if js_findings.get("oauth"):
        add("OAuth2", 20)

    if js_findings.get("oidc"):
        add("OIDC", 20)

    # -------------------------
    # API / Token Signals
    # -------------------------
    if "bearer" in body:
        add("Bearer Token API", 30)

    if "ocp-apim-subscription-key" in str(headers).lower():
        add("Azure API Management", 60)

    if "incapsula" in body:
        add("Imperva WAF", 50)

    # -------------------------
    # Final Decision
    # -------------------------
    if not scores:
        return {
            "provider": "Unknown",
            "protocol": "Unknown",
            "confidence": 0,
            "evidence": []
        }

    best_provider = max(scores, key=scores.get)
    confidence = min(100, scores[best_provider])

    # Protocol inference (lightweight)
    protocol = "Unknown"
    if "OIDC" in scores:
        protocol = "OIDC"
    elif "OAuth2" in scores:
        protocol = "OAuth2"
    elif "SAML" in scores:
        protocol = "SAML"
    elif "Bearer Token API" in scores:
        protocol = "Bearer Token"

    return {
        "provider": best_provider,
        "protocol": protocol,
        "confidence": confidence,
        "scores": scores
    }