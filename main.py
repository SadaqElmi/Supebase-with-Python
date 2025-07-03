# main.py
# A simple FastAPI application that interacts with Supabase to manage a book collection.

from fastapi import FastAPI, HTTPException, Depends, Header, Body
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from typing import List, Optional
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import traceback
# Load environment variables FIRST
load_dotenv()
# Initialize Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError(
        "Supabase URL and Key must be set in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
security = HTTPBearer()
app = FastAPI()


# Updated Signup Model
class SignupData(BaseModel):
    email: str
    password: str
    name: str | None = None  # Optional
    age: int | None = None   # Optional
    bio: str | None = None   # Optional


class LoginData(BaseModel):  # Add this model
    email: str
    password: str


class BookCreate(BaseModel):
    title: str
    author: str


@app.post("/signup")
def signup(user: SignupData):
    try:
        response = supabase.auth.sign_up({
            "email": user.email,
            "password": user.password,
            "options": {
                "data": {
                    "name": user.name,
                    "age": user.age,
                    "bio": user.bio
                }
            }
        })
        return {"message": "User created! Check your email.", "data": response}
    except Exception as e:
        traceback.print_exc()  # Debugging
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/login")
def login(user: LoginData):  # Use the model
    res = supabase.auth.sign_in_with_password({
        "email": user.email,
        "password": user.password
    })
    return res


@app.get("/user/{id}")
def get_user(id: str):
    res = supabase.table("users").select("*").eq("id", id).execute()
    return res.data


# Add Book (only for logged-in users)

async def verify_token(token: str):
    try:
        # Supabase automatically verifies the signature using your project key
        user = supabase.auth.get_user(token)
        return user
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        # Get the full response object
        auth_response = supabase.auth.get_user(credentials.credentials)

        # Access the user object properly
        if not auth_response or not auth_response.user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        return auth_response.user
    except Exception as e:
        print(f"Auth error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")


# Add User Profile Endpoints

# @app.put("/users/me")
# async def update_profile(
#    bio: str = Body(None),
#    age: int = Body(None),
#    current_user=Depends(get_current_user)
# ):
#    supabase.table("users").update({"bio": bio, "age": age}).eq(
#        "id", current_user.id).execute()
#
#    return {"message": "Profile updated successfully"}

@app.put("/users/me")
async def update_profile(
    update_data: dict = Body(...),  # Accept any update fields
    current_user=Depends(get_current_user)
):
    try:
        # Filter None values
        update_fields = {k: v for k, v in update_data.items() if v is not None}

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")

        # Update only provided fields
        response = supabase.table("users")\
            .update(update_fields)\
            .eq("id", current_user.id)\
            .execute()

        return {
            "message": "Profile updated successfully",
            "data": response.data[0] if response.data else None
        }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/books")
async def create_book(
    book: BookCreate,
    current_user=Depends(get_current_user)
):
    try:
        # Debug print to verify user structure
        print(f"Current user: {current_user}")

        book_data = book.dict()
        book_data["user_id"] = current_user.id

        response = supabase.table("books").insert(book_data).execute()

        return response.data[0]
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
