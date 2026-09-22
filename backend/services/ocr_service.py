
import pytesseract
from PIL import Image

# Windows Tesseract OCR installation path
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


def extract_text_from_image(image_path):
    try:
        # Open the image
        image = Image.open(image_path)

        # Extract text using Tesseract OCR
        text = pytesseract.image_to_string(image)

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
