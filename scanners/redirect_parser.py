def parse_redirect_auth(http_data):
    """
    Detect authentication provider signals from redirect chain.
    Phase 1 passive inference only.
    """

    redirects = " ".join(http_data.get("redirect_chain", [])).lower()

    signals = []

    # -------------------------
    # Microsoft Entra ID
    # -------------------------
    if "login.microsoftonline.com" in redirects:
        signals.append({
            "provider": "Microsoft Entra ID",
            "protocol": "OIDC",
            "confidence": 90,
            "evidence": "redirect:login.microsoftonline.com"
        })

    # -------------------------
    # Okta
    # -------------------------
    if "okta.com" in redirects:
        signals.append({
            "provider": "Okta",
            "protocol": "OIDC/SAML",
            "confidence": 85,
            "evidence": "redirect:okta.com"
        })

    # -------------------------
    # Auth0
    # -------------------------
    if "auth0.com" in redirects:
        signals.append({
            "provider": "Auth0",
            "protocol": "OIDC/OAuth2",
            "confidence": 85,
            "evidence": "redirect:auth0.com"
        })

    # -------------------------
    # Keycloak
    # -------------------------
    if "keycloak" in redirects:
        signals.append({
            "provider": "Keycloak",
            "protocol": "OIDC/SAML",
            "confidence": 80,
            "evidence": "redirect:keycloak"
        })

    # -------------------------
    # Generic login behavior
    # -------------------------
    if "/login" in redirects or "/sso" in redirects:
        signals.append({
            "provider": "Generic SSO",
            "protocol": "Unknown",
            "confidence": 50,
            "evidence": "redirect:/login or /sso"
        })

    return signals