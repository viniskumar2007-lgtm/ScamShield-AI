def get_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def get_signal_details(pattern, score):
    signal_map = {
        "urgency": {
            "name": "Urgency / Pressure",
            "severity": "MEDIUM",
            "explanation": "The message pressures the recipient to act immediately."
        },

        "threat": {
            "name": "Account Threat",
            "severity": "HIGH",
            "explanation": "The message uses fear or threats such as account blocking, suspension, or legal action."
        },

        "financial": {
            "name": "Financial Information",
            "severity": "HIGH",
            "explanation": "The message involves banking, payment, money, or financial information."
        },

        "otp_request": {
            "name": "OTP Request",
            "severity": "HIGH",
            "explanation": "The message asks for an OTP or one-time verification code."
        },

        "credential_request": {
            "name": "Credential Request",
            "severity": "HIGH",
            "explanation": "The message requests sensitive credentials such as passwords, PINs, or CVV details."
        },

        "suspicious_action": {
            "name": "Suspicious Action Request",
            "severity": "MEDIUM",
            "explanation": "The recipient is asked to perform an immediate action such as clicking, paying, replying, or sharing information."
        },

        "url": {
            "name": "Suspicious Link",
            "severity": "HIGH",
            "explanation": "The message contains a link that should be verified before opening."
        },

        "suspicious_url": {
            "name": "Suspicious URL",
            "severity": "HIGH",
            "explanation": "The URL contains characteristics commonly associated with suspicious or deceptive links."
        },

        "reward": {
            "name": "Unexpected Reward",
            "severity": "MEDIUM",
            "explanation": "The message offers a prize, reward, cashback, or unexpected benefit that may be used to pressure the recipient."
        },

        "impersonation": {
            "name": "Possible Impersonation",
            "severity": "HIGH",
            "explanation": "The message appears to imitate a trusted company, bank, service, or authority."
        },

        "personal_info": {
            "name": "Personal Information Request",
            "severity": "HIGH",
            "explanation": "The message asks for sensitive personal information."
        }
    }

    details = signal_map.get(
        pattern,
        {
            "name": pattern.replace("_", " ").title(),
            "severity": "MEDIUM",
            "explanation": "A suspicious pattern was detected in the message."
        }
    )

    return {
        "signal": details["name"],
        "score": score,
        "severity": details["severity"],
        "explanation": details["explanation"]
    }


def build_risk_breakdown(rule_result):
    breakdown = []

    detected_patterns = rule_result.get("detected_patterns", [])

    for item in detected_patterns:
        pattern = item.get("pattern")
        score = item.get("score", 0)

        if not pattern:
            continue

        breakdown.append(
            get_signal_details(pattern, score)
        )

    return breakdown


def calculate_hybrid_score(rule_result, ai_result):

    rule_score = rule_result.get("rule_score", 0)
    ai_score = ai_result.get("ai_risk_score", 0)

    # Check whether AI is actually available
    ai_available = ai_result.get("score_mode") != "FALLBACK"

    if ai_available:
        final_score = round(
            (rule_score * 0.6) + (ai_score * 0.4)
        )
        score_mode = "HYBRID"
    else:
        # When Gemini is unavailable, rely more heavily on
        # the real rule-based detector.
        final_score = round(
            (rule_score * 0.85) + (ai_score * 0.15)
        )
        score_mode = "RULE_FALLBACK"

    final_score = max(0, min(100, final_score))

    risk_level = get_risk_level(final_score)

    reasons = rule_result.get("reasons", [])

    if not reasons:
        reasons = ai_result.get("reasons", [])

    recommended_actions = rule_result.get(
        "recommended_actions",
        []
    )

    if not recommended_actions:
        recommended_actions = ai_result.get(
            "recommended_actions",
            []
        )

    scam_type = ai_result.get(
        "scam_type",
        rule_result.get(
            "scam_type",
            "Unknown"
        )
    )

    confidence = max(
        rule_result.get("confidence", 0),
        ai_result.get("confidence", 0)
    )

    # NEW FEATURE 4
    risk_breakdown = build_risk_breakdown(rule_result)

    return {
        "risk_score": final_score,
        "risk_level": risk_level,

        "rule_score": rule_score,
        "ai_score": ai_score,

        "score_mode": score_mode,

        "scam_type": scam_type,
        "confidence": confidence,

        "reasons": reasons,

        "risk_breakdown": risk_breakdown,

        "recommended_actions": recommended_actions
    }