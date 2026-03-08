from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import re
import time
import json

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

def detect_scam(text):
    keywords = ["kyc", "urgent", "verify", "account", "upi", "lottery", "click"]
    score = sum(1 for k in keywords if k in text.lower())
    return score >= 2, min(0.95, 0.6 + score * 0.1)

def extract_intel(text):
    return {
        "bank_accounts": re.findall(r"\b\d{9,18}\b", text),
        "upi_ids": re.findall(r"[\w.-]+@[\w.-]+", text),
        "phishing_links": re.findall(r"https?://[^\s]+", text)
    }

@app.post("/honeypot/message")
async def honeypot(request: Request, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    body = {}

    try:
        raw_body = await request.body()
        if raw_body:
            body = json.loads(raw_body.decode())
    except Exception:
        body = {}

    message_text = ""

    if isinstance(body, dict):
        message = body.get("message", {})

        if isinstance(message, dict):
            message_text = message.get("text", "")
        else:
            message_text = str(message)

    conversation_id = body.get("sessionId", "default")

    start = time.time()
    is_scam, confidence = detect_scam(message_text)

    convo = conversations.setdefault(conversation_id, {
        "turns": 0,
        "intel": {"bank_accounts": [], "upi_ids": [], "phishing_links": []},
        "start_time": start
    })

    convo["turns"] += 1

    intel = extract_intel(message_text)

    for k in convo["intel"]:
        convo["intel"][k] = list(set(convo["intel"][k] + intel[k]))

    # --- Honeypot reply generation ---
    reply = "Why is my account being suspended?"

    if is_scam:
        reply = "I didn't request this. Why is my account being blocked?"

    return {
        "status": "success",
        "reply": reply
    }
