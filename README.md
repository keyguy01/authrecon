# 📡 AuthRecon

## Enterprise Authentication Reconnaissance Tool

AuthRecon is a lightweight Application Security utility that performs **unauthenticated reconnaissance of web applications and APIs** to identify:

* Authentication providers (e.g., Microsoft Entra ID, Okta)
* Authentication protocols (OAuth2, OIDC, SAML, etc.)
* API authentication methods (Bearer tokens, API keys, APIM keys)
* Basic infrastructure signals (Imperva WAF, Azure WAF, API Management gateways)

It is designed for **AppSec inventory and visibility**, not vulnerability scanning.

---

# 🎯 Purpose

Modern enterprise environments often lack visibility into:

* How applications authenticate users
* Which Identity Providers are in use
* Where legacy authentication still exists
* Which APIs are protected by API gateways or subscription keys

AuthRecon solves this by passively analyzing application responses and building an **authentication intelligence inventory**.

---

# ⚙️ Milestone 1 Scope (MVP)

This version focuses on simplicity and usability.

## Supported capabilities:

### 🔍 Discovery

* Read list of domains from `domains.txt`
* HTTP/HTTPS probing (via httpx)
* Redirect chain analysis
* Header inspection
* HTML parsing (login forms, auth signals)
* JavaScript keyword inspection

---

### 🔐 Authentication Detection

AuthRecon identifies:

#### Identity Providers

* Microsoft Entra ID
* Okta
* Ping Identity
* Keycloak
* Auth0
* ADFS
* AWS Cognito

#### Authentication Protocols

* OAuth2
* OpenID Connect (OIDC)
* SAML 2.0
* Basic Authentication
* NTLM
* JWT-based auth
* API Key authentication

---

### 🧱 API & Gateway Detection

* Azure API Management (APIM)
* API subscription key usage (`Ocp-Apim-Subscription-Key`)
* Generic API Gateway patterns
* Bearer token usage

---

### 🛡️ Infrastructure Signals (Lightweight)

* Imperva WAF detection (basic heuristics)
* Azure WAF / Front Door signals
* Reverse proxy detection (basic headers)

---

# 📁 Project Structure

```
AuthRecon/
│
├── authrecon.py              # Main entry point
├── domains.txt               # Input targets
├── config.yaml               # Configuration
├── requirements.txt          # Dependencies
├── README.md
│
├── scanners/                 # Data collection layer
│   ├── httpx_scanner.py
│   ├── html_parser.py
│   └── javascript_parser.py
│
├── fingerprints/             # Detection engine
│   ├── auth_engine.py
│   └── plugins/              # YAML-based rules (future expansion)
│
├── reports/                  # Output generators
│   ├── excel_report.py
│   └── html_report.py
│
└── output/                   # Generated reports
```

---

# 🚀 Getting Started

## 1. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 2. Add target domains

Edit `domains.txt`:

```
https://app1.company.com
https://api.company.com
https://portal.company.com
```

---

## 3. Run AuthRecon

```bash
python authrecon.py
```

---

## 4. View results

Outputs are written to:

```
/output
```

Includes:

* HTML dashboard
* Excel report

---

# 📊 Output Example

| URL                | Auth Provider | Protocol     | API Auth | Infrastructure | Confidence |
| ------------------ | ------------- | ------------ | -------- | -------------- | ---------- |
| portal.company.com | Entra ID      | OIDC         | None     | Imperva WAF    | High       |
| api.company.com    | Unknown       | Bearer Token | APIM Key | Azure APIM     | Medium     |

---

# 🧠 How It Works

AuthRecon follows a simple pipeline:

```
Input URLs
   ↓
HTTP Probe (httpx)
   ↓
Evidence Collection
   ↓
Pattern Matching Engine
   ↓
Authentication Classification
   ↓
Report Generation
```

It does NOT require authentication or credentials.

---

# 🔍 Detection Methodology

AuthRecon uses **evidence-based fingerprinting**, including:

* Redirect URLs
* HTTP response headers
* Cookies
* HTML forms
* JavaScript libraries
* API response patterns

Each finding is assigned a **confidence score based on multiple signals**.

---

# 🛡️ Security Considerations

* No authentication is performed
* No payload injection
* No vulnerability exploitation
* Passive reconnaissance only

This tool is safe for internal AppSec inventory use cases.

---

# 📌 Current Limitations (Milestone 1)

* No browser automation (Playwright not included yet)
* No screenshot capture
* No deep TLS analysis
* No full WAF fingerprint database
* No plugin system yet (basic rules only)
* No historical comparisons

---

# 🧭 Roadmap

## v1.0 (Current)

* Authentication discovery MVP
* Excel + HTML reporting
* Basic infrastructure detection

## v1.1

* YAML plugin system
* WAF + API gateway expansion
* JSON + CSV outputs

## v1.2

* Playwright browser engine
* Login page screenshots
* MFA detection

## v2.0

* Enterprise authentication intelligence platform
* Historical comparison engine
* API + dashboard UI
* CI/CD integrations

---

# 🏢 Intended Use Cases

* Application Security inventory
* IAM architecture visibility
* DAST onboarding preparation
* API security discovery
* Legacy authentication cleanup programs
* Enterprise security architecture mapping

---

# ⚠️ Disclaimer

AuthRecon is designed for authorized security and inventory purposes only.
Users are responsible for ensuring they have permission to scan target systems.

---

# 📄 License

MIT License (recommended for internal extensibility)
