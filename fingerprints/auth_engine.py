def score_findings(http_data, html_findings, js_findings):
    """
    Phase 1 Authentication Scoring Engine

    Responsibilities:
    - Identify auth provider (Entra, Okta, Auth0, Keycloak)
    - Infer protocol (OIDC, OAuth2, SAML)
    - Collect evidence from HTTP/HTML/JS
    - Delegate login type classification
    """

    scores = {}
    evidence = {"http": [], "html": [], "js": []}

    def add(provider, points):
        scores[provider] = scores.get(provider, 0) + points

    headers = http_data.get("headers", {})
    body = http_data.get("body", "").lower()
    redirect_chain = " ".join(http_data.get("redirect_chain", [])).lower()

    # -------------------------
    # Endpoint-based signals
    # -------------------------
    if "/oauth" in body or "/authorize" in body:
        add("OAuth2/OIDC Flow Detected", 40)

    if "/saml" in body:
        add("SAML Flow Detected", 40)

    if "/login" in body or "/signin" in body:
        add("Generic Login Portal", 20)

    # -------------------------
    # HTTP signals
    # -------------------------
    if "login.microsoftonline.com" in body:
        add("Microsoft Entra ID", 50)
        evidence["http"].append("ms login in body")

    if "login.microsoftonline.com" in redirect_chain:
        add("Microsoft Entra ID", 40)
        evidence["http"].append("redirect: Entra")

    if "x-ms-request-id" in str(headers).lower():
        add("Microsoft Entra ID", 20)

    # -------------------------
    # HTML signals
    # -------------------------
    if html_findings.get("saml_hint"):
        add("SAML", 40)
        evidence["html"].append("saml_hint")

    if html_findings.get("oidc_hint"):
        add("OIDC", 40)
        evidence["html"].append("oidc_hint")

    if html_findings.get("oauth_hint"):
        add("OAuth2", 30)
        evidence["html"].append("oauth_hint")

    # -------------------------
    # JS signals
    # -------------------------
    if js_findings.get("msal"):
        add("Microsoft Entra ID", 40)
        evidence["js"].append("msal.js detected")

    if js_findings.get("okta"):
        add("Okta", 40)
        evidence["js"].append("okta sdk detected")

    if js_findings.get("auth0"):
        add("Auth0", 40)
        evidence["js"].append("auth0 sdk detected")

    if js_findings.get("keycloak"):
        add("Keycloak", 40)
        evidence["js"].append("keycloak sdk detected")

    # -------------------------
    # Final decision
    # -------------------------
    if not scores:
        return {
            "provider": "No Auth Signals Detected",
            "protocol": "Unknown (Passive Scan Limit)",
            "confidence": 0,
            "scores": {},
            "evidence": {
                "note": "No auth indicators found in HTTP/HTML/JS"
            }
        }

    best_provider = max(scores, key=scores.get)
    confidence = min(100, scores[best_provider])

    # -------------------------
    # Protocol inference (clean + stable)
    # -------------------------
    protocol = "Unknown"

    keys = " ".join(scores.keys()).lower()

    if "oidc" in keys or "openid" in keys:
        protocol = "OIDC"

    elif "oauth" in keys:
        protocol = "OAuth2"

    elif "saml" in keys:
        protocol = "SAML"

    elif "bearer" in body:
        protocol = "Bearer Token"

    # -------------------------
    # Return structured result
    # -------------------------
    return {
        "provider": best_provider,
        "protocol": protocol,
        "confidence": confidence,
        "scores": scores,
        "evidence": evidence
    }


# =========================================================
# LOGIN TYPE CLASSIFIER (Phase 1 add-on)
# =========================================================

def classify_login_type(body: str, headers: dict, redirect_chain: str):
    """
    Passive login type classification (NO active probing)
    """

    body = (body or "").lower()
    headers_l = {k.lower(): str(v).lower() for k, v in headers.items()}
    redirects = (redirect_chain or "").lower()

    login_type = "Unknown"
    confidence = 0
    evidence = []

    # -------------------------
    # SSO / Federated
    # -------------------------
    if any(x in body for x in ["saml", "openid", "oauth", "oidc"]):
        login_type = "SSO Login (Federated)"
        confidence = 80
        evidence.append("sso_keywords")

    if "login.microsoftonline.com" in redirects:
        login_type = "SSO Login (Microsoft Entra)"
        confidence = 90
        evidence.append("entra_redirect")

    if "okta" in body or "okta" in redirects:
        login_type = "SSO Login (Okta)"
        confidence = 85
        evidence.append("okta_signal")

    if "auth0" in body or "auth0" in redirects:
        login_type = "SSO Login (Auth0)"
        confidence = 85
        evidence.append("auth0_signal")

    # -------------------------
    # Form-based login
    # -------------------------
    if "password" in body and "username" in body:
        login_type = "Form-Based Login"
        confidence = max(confidence, 70)
        evidence.append("username_password_fields")

    if "<form" in body:
        login_type = "Form-Based Login"
        confidence = max(confidence, 60)
        evidence.append("html_form_detected")

    # -------------------------
    # API authentication
    # -------------------------
    if "bearer" in body or "authorization" in headers_l:
        login_type = "API Authentication"
        confidence = max(confidence, 65)
        evidence.append("api_auth")

    # -------------------------
    # WAF-obscured login
    # -------------------------
    if "incapsula" in body or "imperva" in body:
        login_type = "WAF-Protected Login Portal"
        confidence = 50
        evidence.append("imperva_waf")

    # -------------------------
    # Default
    # -------------------------
    if confidence == 0:
        login_type = "Generic Login Portal"
        confidence = 20
        evidence.append("weak_signals")

    return {
        "login_type": login_type,
        "confidence": confidence,
        "evidence": evidence
    }