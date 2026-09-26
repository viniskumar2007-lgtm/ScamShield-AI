import re
import ipaddress
from urllib.parse import urlparse


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "confirm",
    "account",
    "secure",
    "update",
    "bank",
    "payment",
    "refund",
    "reward",
    "prize",
    "free",
    "wallet",
    "otp",
    "password",
    "credential",
]


# ============================================================
# SUSPICIOUS TOP-LEVEL DOMAINS
# ============================================================

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "online",
    "site",
    "info",
    "work",
    "live",
    "buzz",
}


# ============================================================
# URL SHORTENERS
# ============================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "shorturl.at",
    "cutt.ly",
}


# ============================================================
# TRUSTED-LOOKING BRAND NAMES
# ============================================================

BRAND_KEYWORDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "whatsapp",
    "sbi",
    "sbibank",
    "hdfc",
    "hdfcbank",
    "icici",
    "icicibank",
    "axis",
    "axisbank",
    "statebank",
    "phonepe",
    "paytm",
]

OFFICIAL_BRAND_DOMAINS = {
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "paypal": {"paypal.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "sbi": {"sbi.co.in"},
    "sbibank": {"sbi.co.in"},
    "statebank": {"sbi.co.in"},
    "hdfc": {"hdfcbank.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "icicibank": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "axisbank": {"axisbank.com"},
    "phonepe": {"phonepe.com"},
    "paytm": {"paytm.com"},
}


# ============================================================
# HELPERS
# ============================================================

def add_indicator(indicators, indicator, status, score, **extra):
    item = {
        "indicator": indicator,
        "status": status,
        "score": score
    }

    item.update(extra)
    indicators.append(item)


# ============================================================
# URL ANALYZER
# ============================================================

def analyze_url(url):

    url = url.strip()

    if not url:
        return {
            "url": "",
            "domain": "",
            "score": 0,
            "risk_level": "LOW",
            "is_suspicious": False,
            "indicators": [],
            "recommendation": "Enter a URL to analyze."
        }

    # --------------------------------------------------------
    # Normalize URL
    # --------------------------------------------------------

    if len(url) > 2048 or any(ord(c) < 32 for c in url):
        return {"url": url[:2048], "domain": "", "score": 0, "risk_level": "LOW",
                "is_suspicious": False, "indicators": [{"indicator": "Invalid URL", "status": "error", "score": 0}],
                "recommendation": "Enter a valid URL."}
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"url": url, "domain": "", "score": 0, "risk_level": "LOW",
                "is_suspicious": False, "indicators": [{"indicator": "Invalid URL", "status": "error", "score": 0}],
                "recommendation": "Enter a valid HTTP or HTTPS URL."}
    try:
        domain = parsed.hostname or ""
        _ = parsed.port
    except ValueError:
        domain = ""
    if not domain or any(char.isspace() for char in domain):
        return {"url": url, "domain": "", "score": 0, "risk_level": "LOW",
                "is_suspicious": False, "indicators": [{"indicator": "Invalid URL", "status": "error", "score": 0}],
                "recommendation": "Enter a valid URL."}
    domain = domain.lower()

    score = 0
    indicators = []

    # ========================================================
    # 1. HTTPS CHECK
    # ========================================================

    if parsed.scheme == "https":

        add_indicator(
            indicators,
            "HTTPS connection",
            "present",
            0
        )

    else:

        score += 15

        add_indicator(
            indicators,
            "No HTTPS",
            "warning",
            15
        )

    # ========================================================
    # 2. IP ADDRESS CHECK
    # ========================================================

    try:
        is_ip = ipaddress.ip_address(domain).version in (4, 6)
    except ValueError:
        is_ip = False
    if is_ip:

        score += 25

        add_indicator(
            indicators,
            "IP address used instead of domain",
            "warning",
            25
        )

    # ========================================================
    # 3. SUSPICIOUS KEYWORDS
    # ========================================================

    found_keywords = []

    url_lower = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:

        keyword_score = min(
            len(found_keywords) * 5,
            25
        )

        score += keyword_score

        add_indicator(
            indicators,
            "Suspicious keywords",
            "warning",
            keyword_score,
            keywords=found_keywords
        )

    # ========================================================
    # 4. SUSPICIOUS TLD
    # ========================================================

    tld_match = re.search(r"\.([a-z]{2,})$", domain)

    if tld_match:

        tld = tld_match.group(1)

        if tld in SUSPICIOUS_TLDS:

            score += 20

            add_indicator(
                indicators,
                "Suspicious top-level domain",
                "warning",
                20,
                tld=f".{tld}"
            )

    # ========================================================
    # 5. LONG URL
    # ========================================================

    if len(url) > 100:

        score += 10

        add_indicator(
            indicators,
            "Unusually long URL",
            "warning",
            10
        )

    # ========================================================
    # 6. @ SYMBOL
    # ========================================================

    if "@" in url:
        score += 15

        add_indicator(
            indicators,
            "@ symbol detected",
            "warning",
            15
        )

    # ========================================================
    # 7. MANY SUBDOMAINS
    # ========================================================

    subdomain_count = max(
        0,
        len(domain.split(".")) - 2
    )

    if subdomain_count >= 3:

        score += 10

        add_indicator(
            indicators,
            "Multiple subdomains",
            "warning",
            10,
            count=subdomain_count
        )

    # ========================================================
    # 8. URL SHORTENER
    # ========================================================

    if domain in URL_SHORTENERS:

        score += 15

        add_indicator(
            indicators,
            "URL shortener detected",
            "warning",
            15
        )

    # ========================================================
    # 9. SUSPICIOUS PORT
    # ========================================================

    if parsed.port is not None:

        if parsed.port not in (80, 443):

            score += 10

            add_indicator(
                indicators,
                "Non-standard port detected",
                "warning",
                10,
                port=parsed.port
            )

    # ========================================================
    # 10. ENCODED CHARACTERS
    # ========================================================

    if "%" in url:

        score += 5

        add_indicator(
            indicators,
            "Encoded URL characters detected",
            "warning",
            5
        )

    # ========================================================
    # 11. EXCESSIVE HYPHENS
    # ========================================================

    if domain.count("-") >= 3:

        score += 10

        add_indicator(
            indicators,
            "Multiple hyphens in domain",
            "warning",
            10
        )

    # ========================================================
    # 12. BRAND IMPERSONATION SIGNAL
    # ========================================================

    matched_brands = []

    for brand in BRAND_KEYWORDS:

        if re.search(r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])", domain):

            matched_brands.append(brand)

    if matched_brands:

        # A brand name alone is NOT considered a scam.
        # We increase the score only when combined with
        # suspicious URL characteristics.

        labels = domain.split(".")
        registrable_domain = ".".join(labels[-2:]) if len(labels) >= 2 else domain
        official_domain = any(
            registrable_domain == allowed
            for brand in matched_brands
            for allowed in OFFICIAL_BRAND_DOMAINS.get(brand, set())
        )
        suspicious_domain_signal = (
            not official_domain
            or
            parsed.scheme != "https"
            or any(
                indicator["score"] > 0
                for indicator in indicators
                if indicator["indicator"]
                != "Brand name detected"
            )
        )

        if suspicious_domain_signal:

            score += 10

            add_indicator(
                indicators,
                "Possible brand impersonation",
                "warning",
                10,
                brands=matched_brands
            )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(score, 100)

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score >= 60:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # ========================================================
    # SUSPICIOUS FLAG
    # ========================================================

    is_suspicious = score >= 30

    # ========================================================
    # RECOMMENDATION
    # ========================================================

    if risk_level == "HIGH":

        recommendation = (
            "Do not open this link or enter personal information. "
            "Verify the website through the organization's official "
            "website or app."
        )

    elif risk_level == "MEDIUM":

        recommendation = (
            "Use caution with this link. Verify the domain and "
            "website through an official source before continuing."
        )

    else:

        recommendation = (
            "No major URL risk indicators were detected. "
            "Continue to use normal caution."
        )

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "url": url,

        "domain": domain,

        "score": score,

        "risk_level": risk_level,

        "is_suspicious": is_suspicious,

        "indicators": indicators,

        "recommendation": recommendation
    }


def extract_urls(text):
    """Return syntactically bounded URLs, trimming common punctuation."""
    candidates = re.findall(r"(?i)(?:https?://|www\.)[^\s<>'\"]+", text or "")
    return [u.rstrip(".,!?;:)[]}")[:2048] for u in candidates]