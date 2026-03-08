from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import re
import time

app = FastAPI()

@app.get("/")
def root():
    return {"status": "Agentic HoneyPot API running"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = "hunter-secret"

conversations = {}

# -----------------------------
# Scam detection
# -----------------------------
def detect_scam(text):

    keywords = [
        "kyc","urgent","verify","account",
        "upi","lottery","click","blocked","suspend"
    ]

    score = sum(1 for k in keywords if k in text.lower())

    confidence = min(0.95, 0.6 + score * 0.1)

    return score >= 2, confidence


# -----------------------------
# Extract scam intelligence
# -----------------------------
def extract_intel(text):

    return {
        "bank_accounts": re.findall(r"\b\d{9,18}\b", text),
        "upi_ids": re.findall(r"[\w.-]+@[\w.-]+", text),
        "phishing_links": re.findall(r"https?://[^\s]+", text)
    }


# -----------------------------
# Honeypot endpoint
# -----------------------------
@app.post("/honeypot/message")
async def honeypot(request: Request, x_api_key: str = Header(None)):

    # API key validation
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        body = await request.json()
    except:
        body = {}

    # -----------------------------
    # Extract message safely
    # -----------------------------
    message_text = ""

    if isinstance(body.get("message"), dict):
        message_text = body["message"].get("text", "")

    # -----------------------------
    # Conversation session
    # -----------------------------
    session_id = body.get("sessionId", "default")

    is_scam, confidence = detect_scam(message_text)

    intel = extract_intel(message_text)

    convo = conversations.setdefault(session_id, {
        "turns": 0,
        "intel": {"bank_accounts": [], "upi_ids": [], "phishing_links": []},
        "start_time": time.time()
    })

    convo["turns"] += 1

    for key in convo["intel"]:
        convo["intel"][key] = list(set(convo["intel"][key] + intel[key]))

    # -----------------------------
    # Honeypot reply
    # -----------------------------
    reply = "Why is my account being suspended?"

    if is_scam:
        reply = "I didn't request this. Why is my account being blocked?"

    # -----------------------------
    # Required response format
    # -----------------------------
    return {
        "status": "success",
        "reply": reply
    }
