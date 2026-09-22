from services.risk_engine import calculate_hybrid_score


# Simulated Rule Engine result
rule_result = {
    "rule_score": 75,

    "detected_patterns": [
        {
            "pattern": "urgency",
            "score": 15
        },
        {
            "pattern": "otp_request",
            "score": 25
        },
        {
            "pattern": "account_threat",
            "score": 20
        }
    ]
}


# Simulated Gemini result
ai_result = {
    "ai_risk_score": 94,
    "ai_risk_level": "HIGH",
    "scam_type": "Bank Phishing",
    "confidence": 98,

    "reasons": [
        "Creates urgency",
        "Requests OTP",
        "Threatens account suspension"
    ],

    "recommended_actions": [
        "Do not share your OTP",
        "Do not click suspicious links",
        "Contact your bank through its official website"
    ]
}


result = calculate_hybrid_score(
    rule_result,
    ai_result
)


print("\n========== SCAMSHIELD HYBRID ENGINE ==========")

print("Rule Score :", result["rule_score"])
print("AI Score   :", result["ai_score"])

print("----------------------------------------------")

print("FINAL SCORE:", result["risk_score"])
print("RISK LEVEL :", result["risk_level"])

print("SCAM TYPE  :", result["scam_type"])
print("CONFIDENCE :", result["confidence"])

print("\nREASONS:")

for reason in result["reasons"]:
    print("-", reason)

print("\nRECOMMENDED ACTIONS:")

for action in result["recommended_actions"]:
    print("-", action)

print("==============================================")