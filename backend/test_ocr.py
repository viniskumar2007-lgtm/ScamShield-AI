from services.ocr_service import extract_text_from_image


image_path = "test_scam.png"

result = extract_text_from_image(image_path)

print("\n========== SCAMSHIELD OCR TEST ==========")

if result["success"]:

    print("OCR SUCCESS ✅")
    print("\nExtracted Text:")
    print("------------------------------------------")
    print(result["text"])
    print("------------------------------------------")

else:

    print("OCR FAILED ❌")
    print("Error:", result["error"])

print("==========================================")