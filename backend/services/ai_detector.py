import os
import json
import re

from dotenv import load_dotenv
from google import genai
from google.genai import types


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

# You can change this in .env later if needed.
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")


# ============================================================
# GEMINI CLIENT
# ============================================================

client = None

if API_KEY:
    client = genai.Client(
        api_key=API_KEY,
        http_options=types.HttpOptions(
            retry_options=types.HttpRetryOptions(
                attempts=1
            )
        )
    )


# ============================================================
# COMMON JSON STRUCTURE
# ============================================================

def create_result(
    score,
    level,
    scam_type,
    confidence,
    summary,
    reasons,
    recommended_actions
):
    return {
        "ai_risk_score": int(max(0, min(100, score))),
        "ai_risk_level": level,
        "scam_type": scam_type,
        "confidence": int(max(0, min(100, confidence))),
        "summary": summary,
        "reasons": reasons[:5],
        "recommended_actions": recommended_actions[:5]
    }


# ============================================================
# RULE-BASED SECURITY ANALYSIS
# ============================================================

def analyze_with_rules(message):
    """
    Local fallback scam detector.

    This works without Gemini or an internet connection.
    """

    text = message.lower().strip()

    score = 0
    reasons = []
    detected_types = []

    # --------------------------------------------------------
    # 1. URGENCY / PRESSURE
    # --------------------------------------------------------

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\basap\b",
        r"\bact now\b",
        r"\baction required\b",
        r"\blast warning\b",
        r"\bfinal warning\b",
        r"\btoday only\b",
        r"\bwithin \d+\s*(minutes?|hours?)\b",
        r"\bexpires?\b",
        r"\bdeadline\b"
    ]

    urgency_matches = [
        pattern for pattern in urgency_patterns
        if re.search(pattern, text)
    ]

    if urgency_matches:
        score += min(20, len(urgency_matches) * 7)

        reasons.append(
            "Urgent or pressure-based language detected."
        )

        detected_types.append("Social Engineering")

    # --------------------------------------------------------
    # 2. THREAT / FEAR
    # --------------------------------------------------------

    threat_patterns = [
        r"\bblocked\b",
        r"\bsuspended\b",
        r"\bterminated\b",
        r"\bdeactivated\b",
        r"\barrest\b",
        r"\blegal action\b",
        r"\bpolice\b",
        r"\bfine\b",
        r"\bpenalty\b",
        r"\baccount will be closed\b",
        r"\byour account will\b"
    ]

    threat_matches = [
        pattern for pattern in threat_patterns
        if re.search(pattern, text)
    ]

    if threat_matches:
        score += min(20, len(threat_matches) * 8)

        reasons.append(
            "Threatening or fear-inducing language detected."
        )

        detected_types.append("Threat/Pressure Scam")

    # --------------------------------------------------------
    # 3. BANKING / FINANCIAL TERMS
    # --------------------------------------------------------

    financial_patterns = [
        r"\bbank\b",
        r"\baccount\b",
        r"\bcredit card\b",
        r"\bdebit card\b",
        r"\bupi\b",
        r"\bpayment\b",
        r"\btransaction\b",
        r"\brefund\b",
        r"\bwallet\b",
        r"\bnet banking\b",
        r"\bloan\b",
        r"\bkyc\b"
    ]

    financial_matches = [
        pattern for pattern in financial_patterns
        if re.search(pattern, text)
    ]

    if financial_matches:
        score += min(15, len(financial_matches) * 4)

        reasons.append(
            "Financial or banking-related information is involved."
        )

        detected_types.append("Financial Scam")

    # --------------------------------------------------------
    # 4. OTP / PASSWORD / CREDENTIAL REQUEST
    # --------------------------------------------------------

    credential_patterns = [
        r"\botp\b",
        r"\bone[- ]time password\b",
        r"\bpassword\b",
        r"\bpin\b",
        r"\bmpin\b",
        r"\bcvv\b",
        r"\bverification code\b",
        r"\bsecurity code\b",
        r"\blogin details\b",
        r"\bcredentials\b"
    ]

    credential_matches = [
        pattern for pattern in credential_patterns
        if re.search(pattern, text)
    ]

    if credential_matches:
        score += min(25, len(credential_matches) * 8)

        reasons.append(
            "Sensitive credentials or verification information may be requested."
        )

        detected_types.append("Credential Phishing")

    # --------------------------------------------------------
    # 5. SUSPICIOUS ACTION REQUEST
    # --------------------------------------------------------

    action_patterns = [
        r"\bclick\b",
        r"\bclick here\b",
        r"\bverify\b",
        r"\bconfirm\b",
        r"\bactivate\b",
        r"\blogin\b",
        r"\bsign in\b",
        r"\bupdate your\b",
        r"\bdownload\b",
        r"\bopen the link\b",
        r"\bcomplete kyc\b"
    ]

    action_matches = [
        pattern for pattern in action_patterns
        if re.search(pattern, text)
    ]

    if action_matches:
        score += min(15, len(action_matches) * 4)

        reasons.append(
            "The message asks the recipient to perform an immediate action."
        )

        detected_types.append("Phishing")

    # --------------------------------------------------------
    # 6. URL DETECTION
    # --------------------------------------------------------

    url_pattern = r"(https?://\S+|www\.\S+|\b[a-zA-Z0-9-]+\.(com|net|org|info|xyz|top|site|online|click)\b)"

    urls = re.findall(url_pattern, text)

    if urls:
        score += 15

        reasons.append(
            "A link or website address was detected."
        )

        detected_types.append("Link-Based Phishing")

    # --------------------------------------------------------
    # 7. SUSPICIOUS URL CHARACTERISTICS
    # --------------------------------------------------------

    suspicious_url_patterns = [
        r"\.xyz\b",
        r"\.top\b",
        r"\.click\b",
        r"\.online\b",
        r"\.site\b",
        r"\.info\b",
        r"bit\.ly",
        r"tinyurl",
        r"shorturl",
        r"t\.co/",
        r"verify-",
        r"secure-",
        r"login-",
        r"account-"
    ]

    suspicious_url_matches = [
        pattern for pattern in suspicious_url_patterns
        if re.search(pattern, text)
    ]

    if suspicious_url_matches:
        score += min(20, len(suspicious_url_matches) * 7)

        reasons.append(
            "The link contains characteristics commonly associated with suspicious websites."
        )

        detected_types.append("Suspicious Link")

    # --------------------------------------------------------
    # 8. REWARD / PRIZE / TOO-GOOD-TO-BE-TRUE
    # --------------------------------------------------------

    reward_patterns = [
        r"\byou won\b",
        r"\bwon a prize\b",
        r"\blottery\b",
        r"\blucky winner\b",
        r"\bfree money\b",
        r"\bcash prize\b",
        r"\breward\b",
        r"\bbonus\b",
        r"\bclaim your prize\b",
        r"\bcongratulations\b"
    ]

    reward_matches = [
        pattern for pattern in reward_patterns
        if re.search(pattern, text)
    ]

    if reward_matches:
        score += min(20, len(reward_matches) * 7)

        reasons.append(
            "Unexpected reward, prize, or financial benefit is mentioned."
        )

        detected_types.append("Prize/Reward Scam")

    # --------------------------------------------------------
    # 9. IMPERSONATION
    # --------------------------------------------------------

    impersonation_patterns = [
        r"\bcustomer support\b",
        r"\bsupport team\b",
        r"\bbank official\b",
        r"\bgovernment\b",
        r"\btax department\b",
        r"\bincome tax\b",
        r"\bpolice department\b",
        r"\bcourier\b",
        r"\bdelivery team\b",
        r"\btechnical support\b"
    ]

    impersonation_matches = [
        pattern for pattern in impersonation_patterns
        if re.search(pattern, text)
    ]

    if impersonation_matches:
        score += min(15, len(impersonation_matches) * 5)

        reasons.append(
            "The sender may be impersonating an organization or authority."
        )

        detected_types.append("Impersonation")

    # --------------------------------------------------------
    # 10. PERSONAL INFORMATION REQUEST
    # --------------------------------------------------------

    personal_info_patterns = [
        r"\bdate of birth\b",
        r"\baddress\b",
        r"\baadhar\b",
        r"\baadhaar\b",
        r"\bpan card\b",
        r"\bpassport\b",
        r"\bcard number\b",
        r"\baccount number\b",
        r"\bpersonal details\b"
    ]

    personal_matches = [
        pattern for pattern in personal_info_patterns
        if re.search(pattern, text)
    ]

    if personal_matches:
        score += min(15, len(personal_matches) * 5)

        reasons.append(
            "The message may be requesting sensitive personal information."
        )

        detected_types.append("Personal Information Scam")

    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    # --------------------------------------------------------
    # SCAM TYPE
    # --------------------------------------------------------

    if detected_types:
        # Remove duplicates while keeping order
        detected_types = list(dict.fromkeys(detected_types))

        scam_type = detected_types[0]

        if len(detected_types) > 1:
            scam_type = " / ".join(detected_types[:2])
    else:
        scam_type = "None"

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    if score >= 70:
        confidence = min(95, 70 + len(reasons) * 5)
    elif score >= 40:
        confidence = min(85, 55 + len(reasons) * 5)
    else:
        confidence = min(80, 60 + len(reasons) * 5)

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    if level == "HIGH":
        summary = (
            "Multiple scam indicators were detected. "
            "The message should be treated as high risk."
        )

    elif level == "MEDIUM":
        summary = (
            "Some suspicious characteristics were detected. "
            "Verify the message through an official channel."
        )

    else:
        summary = (
            "No strong scam indicators were detected by the "
            "security rules. Continue to use caution."
        )

    # --------------------------------------------------------
    # DEFAULT REASON
    # --------------------------------------------------------

    if not reasons:
        reasons.append(
            "No significant scam indicators were detected."
        )

    # --------------------------------------------------------
    # RECOMMENDED ACTIONS
    # --------------------------------------------------------

    recommended_actions = [
        "Do not click suspicious links.",
        "Do not share OTPs, passwords, PINs, or CVV numbers.",
        "Verify the message through the organization's official website or app.",
        "Do not send money based only on an unexpected message."
    ]

    if level == "HIGH":
        recommended_actions.insert(
            0,
            "Do not respond to the message until its authenticity is verified."
        )

    return create_result(
        score=score,
        level=level,
        scam_type=scam_type,
        confidence=confidence,
        summary=summary,
        reasons=reasons,
        recommended_actions=recommended_actions
    )


# ============================================================
# GEMINI AI ANALYSIS
# ============================================================

def analyze_with_gemini(message):

    if not client:
        raise RuntimeError("Gemini API key is not configured.")

    prompt = f"""
You are ScamShield AI.

Analyze the following message for:
- scams
- phishing
- fraud
- social engineering
- impersonation

MESSAGE:
{message}

Return ONLY valid JSON.

Required format:
{{
    "ai_risk_score": 0,
    "ai_risk_level": "LOW",
    "scam_type": "None",
    "confidence": 0,
    "summary": "",
    "reasons": [],
    "recommended_actions": []
}}

Rules:
- ai_risk_score must be 0-100
- ai_risk_level must be LOW, MEDIUM, or HIGH
- confidence must be 0-100
- reasons maximum 5 items
- recommended_actions maximum 5 items
"""

    interaction = client.interactions.create(
        model=MODEL_NAME,
        input=prompt
    )

    text = interaction.output_text.strip()

    # Remove markdown code fences if Gemini returns them
    if text.startswith("```"):
        text = re.sub(r"^```json\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

    result = json.loads(text)

    # Make sure the expected fields exist
    required_fields = [
        "ai_risk_score",
        "ai_risk_level",
        "scam_type",
        "confidence",
        "summary",
        "reasons",
        "recommended_actions"
    ]

    for field in required_fields:
        if field not in result:
            raise ValueError(
                f"Gemini response missing field: {field}"
            )

    return create_result(
        score=result["ai_risk_score"],
        level=result["ai_risk_level"],
        scam_type=result["scam_type"],
        confidence=result["confidence"],
        summary=result["summary"],
        reasons=result["reasons"],
        recommended_actions=result["recommended_actions"]
    )


# ============================================================
# MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_with_ai(message):

    if not message or not message.strip():
        return create_result(
            score=0,
            level="LOW",
            scam_type="None",
            confidence=100,
            summary="No message was provided for analysis.",
            reasons=[
                "The message input is empty."
            ],
            recommended_actions=[
                "Enter a message to analyze."
            ]
        )

    # --------------------------------------------------------
    # TRY GEMINI
    # --------------------------------------------------------

    if client:

        print("🤖 Sending request to Gemini...")

        try:

            result = analyze_with_gemini(message)

            print("✅ Gemini response received")

            return result

        except Exception as e:

            error_message = str(e).lower()

            # ------------------------------------------------
            # QUOTA / RATE LIMIT
            # ------------------------------------------------

            if (
                "429" in error_message
                or "quota" in error_message
                or "rate limit" in error_message
                or "resource exhausted" in error_message
            ):
                print(
                    "⚠️ Gemini quota unavailable."
                )

            # ------------------------------------------------
            # ANY OTHER GEMINI ERROR
            # ------------------------------------------------

            else:
                print(
                    "⚠️ Gemini unavailable."
                )

            print(
                "🔐 Switching to Security Rule Analysis..."
            )

    else:

        print(
            "⚠️ Gemini API key not configured."
        )

        print(
            "🔐 Using Security Rule Analysis..."
        )

    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    return analyze_with_rules(message)