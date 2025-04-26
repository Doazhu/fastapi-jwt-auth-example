from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
import hashlib
import sqlite3
import uvicorn
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import jwt, JWTError


# Constants
ACCESS_TOKEN_EXPIRE_MINUTES = 1
SECRET_KEY = "09d25e094faa6ca2556c87f29b2929ca004170af3400c48f53514f00961f201d"
ALGORITHM = "HS256"


#  Setup
app = FastAPI(
    title="JWT + HASH example",
    description="API for authentication and authorization",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.swagger_ui_parameters = {
    "usePkceWithAuthorizationCodeGrant": True,
    "clientId": "your-client-id",
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hashed TEXT)")
    conn.commit()
    conn.close()


# Schemas
class User(BaseModel):
    username: str
    password: str
    
class Token(BaseModel):
    access_token: str
    token_type: str


# Methods
async def get_user(username: str):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username, password_hashed FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if user:
        return {"username": user[0], "password_hashed": user[1]}

async def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

async def verify_password(password: str, hashed_password: str):
    return hashlib.sha256(password.encode()).hexdigest() == hashed_password

async def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Routes
@app.post("/api/register")
async def register(user: User):
    if await get_user(user.username):
        raise HTTPException(
            status_code=400,
            detail="User already exists"
        )
    
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password_hashed) VALUES (?, ?)", (user.username, await hash_password(user.password)))
    conn.commit()
    conn.close()
    return {"message": "User registered successfully"}


@app.post("/api/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user(form_data.username)
    if not user or not await verify_password(form_data.password, user["password_hashed"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = await create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/example")
async def example(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"message": "Token is valid", "username": username}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)