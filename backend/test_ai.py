from services.ai_detector import analyze_with_ai


message = """
URGENT! Your bank account will be blocked today.
Send your OTP immediately to verify your account.
"""


result = analyze_with_ai(message)


print("\nSCAMSHIELD AI RESULT")
print("====================")

print(result)