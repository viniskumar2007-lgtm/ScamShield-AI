
from services.url_analyzer import analyze_url


test_urls = [
    "https://www.google.com",
    "http://secure-bank-verify-account.com/login",
    "https://sbi-account-update.example.com/verify"
]

print("\n========== SCAMSHIELD URL TEST ==========\n")

for url in test_urls:
    print("URL:", url)
    print("------------------------------------------")

    result = analyze_url(url)

    print("Risk Score:", result["score"])
    print("Risk Level:", result["risk_level"])
    print("Domain:", result["domain"])

    print("\nIndicators:")

    for indicator in result["indicators"]:
        print("  -", indicator)

    print("\n==========================================\n")
