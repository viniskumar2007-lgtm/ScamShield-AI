
import pytesseract
from PIL import Image, ImageOps
import os
import shutil

configured_tesseract = os.getenv("TESSERACT_CMD")
windows_tesseract = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if configured_tesseract:
    pytesseract.pytesseract.tesseract_cmd = configured_tesseract
elif os.path.exists(windows_tesseract):
    pytesseract.pytesseract.tesseract_cmd = windows_tesseract
elif shutil.which("tesseract"):
    pytesseract.pytesseract.tesseract_cmd = shutil.which("tesseract")


def extract_text_from_image(image_path, languages=None, preprocess=True):
    try:
        image = Image.open(image_path)
        max_image_pixels = int(os.getenv("MAX_IMAGE_PIXELS", "20000000"))
        if image.width * image.height > max_image_pixels:
            raise ValueError("Image dimensions exceed the configured OCR pixel limit.")

        if preprocess:
            image.thumbnail((2400, 2400))
            if max(image.size) < 1200:
                image = image.resize(
                    (image.width * 2, image.height * 2),
                    Image.Resampling.LANCZOS,
                )
            image = ImageOps.autocontrast(image.convert("L"))
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
