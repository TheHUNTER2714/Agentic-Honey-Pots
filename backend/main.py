from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
DEFAULT_REPLY = "Why is my account being suspended?"


class MessagePayload(BaseModel):
    sender: Optional[str] = None
    text: Optional[str] = None
    timestamp: Optional[int] = None


class HoneypotRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Optional[Union[MessagePayload, str]] = None
    conversationHistory: Optional[List[Any]] = None
    metadata: Optional[Dict[str, Any]] = None


def is_valid_api_key(
    x_api_key: Optional[str],
    api_key: Optional[str],
    authorization: Optional[str],
) -> bool:
    if x_api_key == API_KEY or api_key == API_KEY:
        return True

    if authorization:
        normalized = authorization.strip()
        if normalized == API_KEY:
            return True
        if normalized.lower().startswith("bearer ") and normalized[7:].strip() == API_KEY:
            return True

    return False


@app.post("/honeypot/message")
async def honeypot(
    payload: Optional[HoneypotRequest] = None,
    x_api_key: Optional[str] = Header(default=None),
    api_key: Optional[str] = Header(default=None, alias="API-KEY"),
    authorization: Optional[str] = Header(default=None),
):
    if not is_valid_api_key(x_api_key, api_key, authorization):
        raise HTTPException(status_code=401, detail="Invalid API key")

    _ = payload

    return {
        "status": "success",
        "reply": DEFAULT_REPLY,
    }
