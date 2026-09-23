import logging
import os
import tempfile
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict, Field, field_validator

if __package__:
    from .services.ai_detector import analyze_with_ai
    from .services.history import HistoryStore
    from .services.ocr_service import extract_text_from_image
    from .services.reputation import get_reputation_provider
    from .services.risk_engine import calculate_hybrid_score
    from .services.rule_engine import calculate_rule_score
    from .services.url_analyzer import analyze_url
else:
    from services.ai_detector import analyze_with_ai
    from services.history import HistoryStore
    from services.ocr_service import extract_text_from_image
    from services.reputation import get_reputation_provider
    from services.risk_engine import calculate_hybrid_score
    from services.rule_engine import calculate_rule_score
    from services.url_analyzer import analyze_url

logger = logging.getLogger("scamshield")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
MAX_MESSAGE = int(os.getenv("MAX_MESSAGE_LENGTH", "20000"))
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_BYTES", str(8 * 1024 * 1024)))
MAX_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", "16000000"))
ALLOWED_MIME = {"image/png", "image/jpeg"}
TRUSTED_AUTH_PROXY = os.getenv("TRUSTED_AUTH_PROXY", "").lower() in {"1", "true", "yes"}
metrics = {"requests": 0, "analyses": 0, "errors": 0}
history = HistoryStore(os.getenv("HISTORY_DB", "scamshield.db"),
                       int(os.getenv("HISTORY_RETENTION_DAYS", "30")))


class TextRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    message: str = Field(min_length=1, max_length=MAX_MESSAGE)


class URLRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def no_control_chars(cls, value):
        if any(ord(c) < 32 for c in value):
            raise ValueError("URL contains control characters")
        return value


def identity(owner_id: Annotated[str | None, Header(alias="X-Authenticated-User")] = None) -> str:
    """Accept identity only when a separately configured trusted gateway is present."""
    if not TRUSTED_AUTH_PROXY:
        raise HTTPException(503, "History authentication is not configured")
    if not owner_id or len(owner_id) > 128:
        raise HTTPException(401, "Authenticated identity required for history")
    return owner_id


@asynccontextmanager
async def lifespan(_app):
    history.purge()
    yield


app = FastAPI(title="ScamShield AI", version="2.1", lifespan=lifespan)
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-Request-ID", "X-Authenticated-User"])


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    metrics["requests"] += 1
    try:
        response = await call_next(request)
    except Exception:
        metrics["errors"] += 1
        logger.exception("request_failed request_id=%s path=%s", request_id, request.url.path)
        response = JSONResponse(status_code=500, content={"success": False, "error": {"code": "internal_error", "message": "Internal server error"}, "request_id": request_id})
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_request, exc):
    return JSONResponse(status_code=422, content={"success": False, "error": {"code": "validation_error", "details": exc.errors()}})


@app.exception_handler(HTTPException)
async def http_error(_request, exc):
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(status_code=exc.status_code,
                        content={"success": False, "error": {"code": "request_error", "message": message}})


def analyze_text(message: str) -> dict:
    metrics["analyses"] += 1
    rules = calculate_rule_score(message)
    ai = analyze_with_ai(message)
    return {"success": True, "message": message, "ai_analysis": ai,
            "rule_analysis": rules, "final_analysis": calculate_hybrid_score(rules, ai)}


@app.get("/")
def home():
    return {"message": "ScamShield AI is running", "version": app.version}


@app.get("/health")
def health():
    return {"status": "healthy", "checks": {"database": "ok", "reputation": "optional"}}


@app.get("/metrics")
def metrics_endpoint():
    return {"requests_total": metrics["requests"], "analyses_total": metrics["analyses"], "errors_total": metrics["errors"]}


@app.get("/api/extension/capabilities")
def extension_capabilities():
    return {"version": app.version, "analyze_endpoint": "/api/extension/analyze",
            "supported_inputs": ["text", "url"], "authentication": "browser extension must supply its host authentication"}


@app.post("/api/analyze")
def analyze_message(request: TextRequest):
    return analyze_text(request.message)


@app.post("/api/extension/analyze")
def extension_analyze(request: TextRequest):
    return analyze_text(request.message)


@app.post("/api/analyze-url")
def analyze_url_endpoint(request: URLRequest):
    return {"success": True, "url_analysis": analyze_url(request.url)}


async def read_image(file: UploadFile) -> tuple[bytes, str]:
    if file.content_type not in ALLOWED_MIME:
        raise HTTPException(415, "Only PNG and JPEG images are supported")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "Image exceeds the upload size limit")
    try:
        with Image.open(__import__("io").BytesIO(data)) as image:
            if image.format not in {"PNG", "JPEG"}:
                raise HTTPException(415, "Image MIME does not match its content")
            if image.width * image.height > MAX_PIXELS:
                raise HTTPException(413, "Image dimensions exceed the limit")
    except UnidentifiedImageError:
        raise HTTPException(415, "Invalid image")
    return data, ".png" if file.content_type == "image/png" else ".jpg"


@app.post("/api/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    data, suffix = await read_image(file)
    path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
            temp.write(data)
            path = temp.name
        languages = os.getenv("OCR_LANGUAGES", "eng")
        ocr = extract_text_from_image(path, languages=languages)
        if not ocr["success"]:
            raise HTTPException(422, ocr.get("error", "OCR failed"))
        text = ocr["text"]
        if not text.strip():
            raise HTTPException(422, "No readable text was found in the screenshot")
        result = analyze_text(text)
        result.update({"filename": file.filename, "extracted_text": text})
        return result
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                logger.warning("temporary file cleanup failed")


@app.get("/api/history")
def list_history(owner_id: str = Depends(identity), limit: int = 50):
    return {"items": history.list(owner_id, max(1, min(limit, 100)))}


@app.delete("/api/history/{scan_id}")
def delete_history(scan_id: int, owner_id: str = Depends(identity)):
    if not history.delete(owner_id, scan_id):
        raise HTTPException(404, "History item not found")
    return {"deleted": True}


@app.post("/api/history")
def save_history(payload: dict, owner_id: str = Depends(identity)):
    if len(str(payload)) > MAX_MESSAGE * 2:
        raise HTTPException(413, "History item is too large")
    return {"id": history.add(owner_id, str(payload.get("kind", "analysis")), payload)}
