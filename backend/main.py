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

    # --- universal body parsing ---
    try:
        raw_body = await request.body()
        if raw_body:
            body = json.loads(raw_body.decode())
    except Exception:
        body = {}

    # fallback to form/query
    if not body:
        try:
            form_data = await request.form()
            body = dict(form_data)
        except Exception:
            body = dict(request.query_params)

    # --- extract message safely ---
    message_text = ""

    if isinstance(body, dict):
        message_text = (
            body.get("message")
            or body.get("text")
            or body.get("content")
            or ""
        )

        if not message_text:
            data = body.get("data") or body.get("payload") or {}
            if isinstance(data, dict):
                message_text = (
                    data.get("message")
                    or data.get("text")
                    or data.get("content")
                    or ""
                )

    message_text = str(message_text)

    # --- conversation id ---
    conversation_id = (
        body.get("conversation_id")
        or body.get("conversationId")
        or body.get("session_id")
        or body.get("sessionId")
        or body.get("conversation")
        or "default"
    )

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

    return {
        "scam_detected": is_scam,
        "confidence": confidence,
        "agent_reply": "Thank you, can you provide more details?",
        "engagement": {
            "conversation_turns": convo["turns"],
            "duration_seconds": int(time.time() - convo["start_time"])
        },
        "extracted_intelligence": convo["intel"]
    }
