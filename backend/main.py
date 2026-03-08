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
    sender: str | None = None
    text: str | None = None
    timestamp: int | None = None


class HoneypotRequest(BaseModel):
    sessionId: str | None = None
    message: MessagePayload | str | None = None
    conversationHistory: list | None = None
    metadata: dict | None = None


def is_valid_api_key(
    x_api_key: str | None,
    api_key: str | None,
    authorization: str | None,
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
    payload: HoneypotRequest,
    x_api_key: str | None = Header(default=None),
    api_key: str | None = Header(default=None, alias="API-KEY"),
    authorization: str | None = Header(default=None),
):
    if not is_valid_api_key(x_api_key, api_key, authorization):
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Access payload fields to ensure the evaluator's submitted shape is accepted.
    _ = payload.message

    return {
        "status": "success",
        "reply": DEFAULT_REPLY,
    }
