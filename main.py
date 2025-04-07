from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sonnylabs_py import SonnyLabsClient

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up the Jinja2 templates directory
templates = Jinja2Templates(directory="templates")

# Initialize the SonnyLabs client
client = SonnyLabsClient(
    api_token="18e0e9c6-c447-4712-bd52-ec8fd6a5f19e",  # replace with your actual API key
    base_url="https://sonnylabs-service.onrender.com",
    analysis_id=12,
)


@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_text(request: Request, text: str = Form(...)):
    # Analyze the text using SonnyLabs client
    result = client.analyze_text(text, scan_type="input")
    
    # Process the analysis result to extract PII entries
    pii_results = []
    for analysis in result.get("analysis", []):
        if analysis.get("type") == "PII":
            # Extend with all found PII entries
            pii_results.extend(analysis.get("result", []))
    
    # Pass the original text and the extracted PII items to the template
    return templates.TemplateResponse("result.html", {
        "request": request,
        "pii_results": pii_results,
        "text": text
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
