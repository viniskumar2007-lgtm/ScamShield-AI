import re


# Scam keywords and their risk points
SCAM_PATTERNS = {

    "urgency": {
        "keywords": [
            "urgent",
            "immediately",
            "act now",
            "right now",
            "within 10 minutes",
            "within 24 hours",
            "limited time",
            "hurry"
        ],
        "score": 15
    },

    "otp_request": {
        "keywords": [
            "otp",
            "one time password",
            "verification code",
            "security code",
            "send the code",
            "share the code"
        ],
        "score": 25
    },

    "payment_request": {
        "keywords": [
            "send money",
            "pay now",
            "make payment",
            "payment required",
            "processing fee",
            "registration fee",
            "upi",
            "gift card",
            "transfer money"
        ],
        "score": 25
    },

    "account_threat": {
        "keywords": [
            "account blocked",
            "account will be blocked",
            "account suspended",
            "account will be suspended",
            "account disabled",
            "account will be closed",
            "legal action",
            "police case",
            "arrest",
            "penalty"
        ],
        "score": 20
    },

    "prize_scam": {
        "keywords": [
            "you won",
            "congratulations",
            "lottery",
            "prize",
            "reward",
            "free money",
            "cash prize",
            "winner"
        ],
        "score": 15
    },

    "job_scam": {
        "keywords": [
            "guaranteed job",
            "work from home",
            "earn money",
            "easy money",
            "job offer",
            "registration fee",
            "joining fee",
            "interview fee"
        ],
        "score": 15
    },

    "credential_request": {
        "keywords": [
            "password",
            "pin",
            "cvv",
            "credit card",
            "debit card",
            "login details",
            "username",
            "account details",
            "bank details"
        ],
        "score": 25
    },

    "impersonation": {
        "keywords": [
            "bank",
            "sbi",
            "hdfc",
            "icici",
            "axis bank",
            "paypal",
            "amazon",
            "flipkart",
            "google",
            "microsoft",
            "income tax",
            "government"
        ],
        "score": 10
    }
}


def detect_suspicious_urls(text):
    """
    Detect URLs inside a message.
    """

    url_pattern = r"https?://[^\s]+|www\.[^\s]+"

    urls = re.findall(url_pattern, text.lower())

    if urls:
        return urls

    return []


def calculate_rule_score(text):
    """
    Analyze text using predefined scam detection rules.
    """

    text_lower = text.lower()

    score = 0
    detected_patterns = []
    matched_keywords = []

    for pattern_name, pattern_data in SCAM_PATTERNS.items():

        pattern_detected = False

        for keyword in pattern_data["keywords"]:

            if keyword in text_lower:

                pattern_detected = True

                if keyword not in matched_keywords:
                    matched_keywords.append(keyword)

        if pattern_detected:

            score += pattern_data["score"]

            detected_patterns.append({
                "pattern": pattern_name,
                "score": pattern_data["score"]
            })

    # Detect suspicious URLs
    urls = detect_suspicious_urls(text)

    if urls:

        score += 20

        detected_patterns.append({
            "pattern": "suspicious_url",
            "score": 20
        })

    # Limit score to 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = "HIGH"

    elif score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "rule_score": score,
        "risk_level": risk_level,
        "detected_patterns": detected_patterns,
        "matched_keywords": matched_keywords,
        "urls_detected": urls
    }