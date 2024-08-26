from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pymongo import MongoClient, errors as pymongo_errors
from bson.objectid import ObjectId
import bcrypt
from starlette.middleware.sessions import SessionMiddleware
import os
from dotenv import load_dotenv
import jwt
from typing import Optional

load_dotenv()  # Load environment variables

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY', 'secretKey'), max_age=1800)  # 30 minutes

templates = Jinja2Templates(directory="templates")
client = MongoClient("mongodb://127.0.0.1:27017/")
db = client["mydatabase"]
users = db["users"]

SECRET_KEY = os.getenv('SECRET_KEY', 'secretKey')
ALGORITHM = "HS256"

class UserModel(BaseModel):
    username: str
    password: str

class RegisterModel(BaseModel):
    username: str
    password: str
    confirm_password: str

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(request: Request):
    token = request.headers.get("Authorization")
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = token.replace("Bearer ", "")
    payload = verify_token(token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = users.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

@app.get("/users/me/")
async def get_me(request: Request):
    try:
        user = get_current_user(request)
        return {"username": user["username"]}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.get("/login")
async def login(request: Request, message: str = None):
    try:
        message = request.query_params.get("message", "")
        return templates.TemplateResponse("login.html", {"request": request, "message": message})
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.post("/login")
async def post_login(request: Request):
    try:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")

        # Fetch the user from the database
        user = users.find_one({"username": username})
        if not user:
            return RedirectResponse(url="/login?message=User does not exist", status_code=status.HTTP_302_FOUND)

        # Ensure the password from the database is in bytes before comparison
        stored_hashed_password = user['password']
        if isinstance(stored_hashed_password, str):
            stored_hashed_password = stored_hashed_password.encode('utf-8')

        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            return RedirectResponse(url="/login?message=Invalid password", status_code=status.HTTP_302_FOUND)

        # Generate JWT token
        token = jwt.encode({"sub": username}, SECRET_KEY, algorithm=ALGORITHM)
        response = RedirectResponse(url="/protected?message=Login successful", status_code=status.HTTP_302_FOUND)
        response.set_cookie(key="access_token", value=f"Bearer {token}")
        return response
    except pymongo_errors.PyMongoError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error: " + str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.get("/protected")
async def protected(request: Request, message: str = None):
    try:
        if 'user' not in request.session:
            message = request.query_params.get("message", "")
            return RedirectResponse(url="/login?message=Session expired. Please log in again.", status_code=status.HTTP_302_FOUND)

        return templates.TemplateResponse("protected.html", {"request": request, "user": request.session['user'], "message": message})
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.get("/logout")
async def logout(request: Request):
    try:
        response = RedirectResponse(url="/login?message=You have been logged out.", status_code=status.HTTP_302_FOUND)
        response.delete_cookie("access_token")
        return response
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.get("/register")
async def register(request: Request, message: str = None):
    try:
        message = request.query_params.get("message", "")
        return templates.TemplateResponse("register.html", {"request": request, "message": message})
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.post("/register")
async def post_register(request: Request):
    try:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        confirm_password = form.get("confirm_password")

        if password != confirm_password:
            return RedirectResponse(url="/register?message=Passwords do not match", status_code=status.HTTP_302_FOUND)

        if not username or not password or not confirm_password:
            return RedirectResponse(url="/register?message=Please fill in all fields", status_code=status.HTTP_302_FOUND)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users.insert_one({"username": username, "password": hashed_password})

        return RedirectResponse(url="/login?message=Registration successful. Please log in.", status_code=status.HTTP_302_FOUND)
    except pymongo_errors.PyMongoError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error: " + str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
