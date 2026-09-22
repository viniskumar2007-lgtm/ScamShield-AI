
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import tempfile
import os

from services.ai_detector import analyze_with_ai
from services.rule_engine import calculate_rule_score
from services.risk_engine import calculate_hybrid_score
from services.url_analyzer import analyze_url
from services.ocr_service import extract_text_from_image


# ======================================================
# APP CONFIGURATION
# ======================================================

app = FastAPI(
    title="ScamShield AI",
    description="AI-powered hybrid scam detection API",
    version="2.0"
)


# ======================================================
# CORS
# ======================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================
# REQUEST MODELS
# ======================================================

class MessageRequest(BaseModel):
    message: str


class URLRequest(BaseModel):
    url: str


# ======================================================
# HOME
# ======================================================

@app.get("/")
def home():
    return {
        "message": "ScamShield AI is running 🚨"
    }


# ======================================================
# HEALTH CHECK
# ======================================================

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ======================================================
# MESSAGE ANALYZER
# ======================================================

@app.post("/api/analyze")
def analyze_message(request: MessageRequest):

    # 1. Rule-based analysis
    rule_result = calculate_rule_score(
        request.message
    )

    # 2. AI analysis
    ai_result = analyze_with_ai(
        request.message
    )

    # 3. Hybrid risk analysis
    final_result = calculate_hybrid_score(
        rule_result,
        ai_result
    )

    return {
        "success": True,
        "message": request.message,

        "ai_analysis": ai_result,

        "rule_analysis": rule_result,

        "final_analysis": final_result
    }


# ======================================================
# SCREENSHOT ANALYZER
# ======================================================

@app.post("/api/analyze-image")
async def analyze_image(file: UploadFile = File(...)):

    # Check whether a file was uploaded
    if not file:
        return {
            "success": False,
            "error": "No image uploaded."
        }

    # Allowed image formats
    allowed_extensions = {
        ".png",
        ".jpg",
        ".jpeg"
    }

    # Get file extension
    suffix = os.path.splitext(
        file.filename or ""
    )[1].lower()

    if suffix not in allowed_extensions:
        return {
            "success": False,
            "error": "Only PNG, JPG and JPEG images are supported."
        }

    # Create temporary file
    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as temp_file:

            file_data = await file.read()

            temp_file.write(file_data)

            temp_path = temp_file.name

        # ==================================================
        # STEP 1: OCR
        # ==================================================

        # OCR
        print("🔍 Starting OCR...")

        ocr_result = extract_text_from_image(
            temp_path
        )

        print("✅ OCR completed")

        if not ocr_result["success"]:

            return {
                "success": False,
                "error": ocr_result.get(
                    "error",
                    "OCR failed."
                )
            }

        extracted_text = ocr_result["text"]

        # Check if OCR found text
        if not extracted_text.strip():

            return {
                "success": False,
                "error": "No readable text was found in the screenshot."
            }

        # ==================================================
        # STEP 2: RULE ENGINE
        # ==================================================

        rule_result = calculate_rule_score(
            extracted_text
        )

        # ==================================================
        # STEP 3: AI ANALYSIS
        # ==================================================

                # AI
        print("🤖 Starting AI analysis...")

        ai_result = analyze_with_ai(
            extracted_text
        )

        print("✅ AI analysis completed")

        # ==================================================
        # STEP 4: HYBRID RISK ENGINE
        # ==================================================

        final_result = calculate_hybrid_score(
            rule_result,
            ai_result
        )

        # ==================================================
        # FINAL RESPONSE
        # ==================================================

        return {
            "success": True,

            "filename": file.filename,

            "extracted_text": extracted_text,

            "ai_analysis": ai_result,

            "rule_analysis": rule_result,

            "final_analysis": final_result
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }

    finally:

        # Delete temporary file
        if temp_path and os.path.exists(temp_path):

            os.remove(temp_path)


# ======================================================
# URL ANALYZER
# ======================================================

@app.post("/api/analyze-url")
def analyze_url_endpoint(request: URLRequest):

    result = analyze_url(
        request.url
    )

    return {
        "success": True,
        "url_analysis": result
    }

