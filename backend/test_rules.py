from services.rule_engine import calculate_rule_score


message = """
URGENT! Your bank account will be blocked today.
Send your OTP immediately to verify your account.
"""


result = calculate_rule_score(message)


print("\n========== SCAMSHIELD RULE ENGINE ==========")

print("Rule Score:", result["rule_score"])
print("Risk Level:", result["risk_level"])

print("\nDetected Patterns:")

for pattern in result["detected_patterns"]:
    print(
        "-",
        pattern["pattern"],
        "+",
        pattern["score"]
    )

print("\nMatched Keywords:")

for keyword in result["matched_keywords"]:
    print("-", keyword)

print("\nURLs Detected:")

for url in result["urls_detected"]:
    print("-", url)

print("\n============================================")