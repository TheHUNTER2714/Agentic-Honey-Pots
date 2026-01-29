from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import time

app = FastAPI()

@app.get("/")
def root():
    return {"status": "Agentic HoneyPot API running"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow frontend
    allow_credentials=True,
    allow_methods=["*"],  # allow POST, OPTIONS
    allow_headers=["*"],  # allow X-API-KEY
)

API_KEY = "hunter-secret"
conversations = {}

class Message(BaseModel):
    conversation_id: str
    message: str

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
def honeypot(msg: Message, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    start = time.time()
    is_scam, confidence = detect_scam(msg.message)

    convo = conversations.setdefault(msg.conversation_id, {
        "turns": 0,
        "intel": {"bank_accounts": [], "upi_ids": [], "phishing_links": []},
        "start_time": start
    })

    convo["turns"] += 1
    intel = extract_intel(msg.message)

    for k in convo["intel"]:
        convo["intel"][k].extend(intel[k])

    return {
        "scam_detected": is_scam,
        "confidence": confidence,
        "engagement": {
            "conversation_turns": convo["turns"],
            "duration_seconds": int(time.time() - convo["start_time"])
        },
        "extracted_intelligence": convo["intel"]
    }
