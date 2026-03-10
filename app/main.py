from fastapi import FastAPI, Header, HTTPException, Depends
from typing import Optional
from dotenv import load_dotenv
import os
import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

load_dotenv()

app = FastAPI()

API_KEY = os.getenv("API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

bearer_scheme = HTTPBearer()

MESSAGES = [
    {"id": 1, "user_id": 1, "text": "Welcome to the platform!"},
    {"id": 2, "user_id": 2, "text": "Your report is ready for download."},
    {"id": 3, "user_id": 1, "text": "You have a new notification."},
    {"id": 4, "user_id": 3, "text": "Password will expire in 5 days."},
    {"id": 5, "user_id": 2, "text": "New login detected from a new device."},
    {"id": 6, "user_id": 3, "text": "Your subscription has been updated."},
]


@app.get("/")
def public_root():
    return {"message": "Welcome to the secured cloud API!"}


@app.get("/secret")
def protected_secret(x_api_key: Optional[str] = Header(default=None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing API key")
    return {"secret": "This is protected data."}


@app.get("/messages")
def protected_messages(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    sub = payload.get("sub")
    role = payload.get("role")

    if sub is None or role is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        sub = int(sub)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid sub value")

    if role == "admin":
        return MESSAGES

    return [msg for msg in MESSAGES if msg["user_id"] == sub]