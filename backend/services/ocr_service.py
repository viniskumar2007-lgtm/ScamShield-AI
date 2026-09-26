
import pytesseract
from PIL import Image
import os

# Windows Tesseract OCR installation path
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


def extract_text_from_image(image_path, languages=None, preprocess=True):
    try:
        # Open the image
        image = Image.open(image_path)

        if preprocess:
            image = image.convert("RGB")
            image.thumbnail((2400, 2400))
        langs = languages or os.getenv("OCR_LANGUAGES", "eng")
        text = pytesseract.image_to_string(image, lang=langs)

        return {
            "success": True,
            "text": text.strip()
        }

    except Exception as e:
        return {
            "success": False,
            "text": "",
            "error": str(e)
        }
