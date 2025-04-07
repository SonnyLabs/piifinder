from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sonnylabs_py import SonnyLabsClient
import re
from typing import Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import html
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Add CORS middleware with specific origins
allowed_origins = [
    "http://localhost:8000",  # Local development
    "http://localhost:3000",  # Common frontend port
    "https://pii-finder-c64c00d500cf.herokuapp.com/",  # Replace with your actual Heroku app URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Only allow necessary methods
    allow_headers=["*"],
)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up the Jinja2 templates directory
templates = Jinja2Templates(directory="templates")

# Initialize the SonnyLabs client with environment variables
client = SonnyLabsClient(
    api_token=os.getenv("SONNYLABS_API_TOKEN"),
    base_url=os.getenv("SONNYLABS_BASE_URL"),
    analysis_id=int(os.getenv("SONNYLABS_ANALYSIS_ID")),
)

def sanitize_input(text: str) -> str:
    """Sanitize input text to prevent XSS and other attacks."""
    # Remove potentially dangerous characters
    text = re.sub(r'[<>]', '', text)
    # HTML escape the text
    text = html.escape(text)
    return text

def validate_text_length(text: str) -> None:
    """Validate text length to prevent DoS attacks."""
    max_length = 10000  # Adjust based on your needs
    if len(text) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"Text is too long. Maximum length is {max_length} characters."
        )

@app.get("/", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def read_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})

@app.post("/analyze", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def analyze_text(
    request: Request,
    text: str = Form(...),
):
    try:
        # Validate input length
        validate_text_length(text)
        
        # Sanitize input
        sanitized_text = sanitize_input(text)
        
        # Analyze the text using SonnyLabs client
        result = client.analyze_text(sanitized_text, scan_type="input")
        
        # Process the analysis result to extract PII entries
        pii_results = []
        for analysis in result.get("analysis", []):
            if analysis.get("type") == "PII":
                # Sanitize PII results
                sanitized_results = []
                for pii in analysis.get("result", []):
                    sanitized_pii = {
                        "text": sanitize_input(pii.get("text", "")),
                        "label": sanitize_input(pii.get("label", ""))
                    }
                    sanitized_results.append(sanitized_pii)
                pii_results.extend(sanitized_results)
        
        # Pass the original text and the extracted PII items to the template
        return templates.TemplateResponse("result.html", {
            "request": request,
            "pii_results": pii_results,
            "text": sanitized_text
        })
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request."
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
