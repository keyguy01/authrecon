from bs4 import BeautifulSoup


def parse_html_for_auth(evidence: dict):
    """
    Extract authentication signals from HTML content.
    """

    html = evidence.get("body", "")
    soup = BeautifulSoup(html, "html.parser")

    findings = {
        "login_form": False,
        "password_field": False,
        "oauth_hint": False,
        "saml_hint": False,
        "oidc_hint": False,
        "auth_keywords": []
    }

    text = html.lower()

    # ---------------- Login form detection ----------------
    forms = soup.find_all("form")
    for form in forms:
        form_text = str(form).lower()

        if "login" in form_text or "signin" in form_text:
            findings["login_form"] = True

        if "password" in form_text:
            findings["password_field"] = True

    # ---------------- Keyword detection ----------------
    keywords = [
        "oauth", "authorize", "token",
        "saml", "sso", "openid",
        "oidc", "login.microsoftonline",
        "okta", "auth0", "keycloak"
    ]

    for kw in keywords:
        if kw in text:
            findings["auth_keywords"].append(kw)

    # ---------------- Protocol hints ----------------
    if "saml" in text:
        findings["saml_hint"] = True

    if "openid" in text or "oidc" in text:
        findings["oidc_hint"] = True

    if "oauth" in text:
        findings["oauth_hint"] = True

    return findings