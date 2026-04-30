from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

import database
from auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    get_current_user,
    get_user_by_username,
    hash_password,
)
from models import LoginRequest, Token, UserCreate, UserModel, UserResponse

#App setup

app = FastAPI(
    title="FastAPI JWT Auth",
    description="A minimal but production-ready JWT authentication service.",
    version="1.0.0",
)

# Create all database tables on startup
database.Base.metadata.create_all(bind=database.engine)


#Auth routes

@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(database.get_db)):
    """
    Register a new user.

    - Checks that neither username nor email is already taken.
    - Stores a bcrypt hash of the password (never the plain-text).
    """
    if get_user_by_username(db, user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    if db.query(UserModel).filter(UserModel.email == user_in.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    new_user = UserModel(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/auth/login", response_model=Token)
def login(credentials: LoginRequest, db: Session = Depends(database.get_db)):
    """
    Authenticate a user and return a signed JWT access token.

    The token encodes the username in the `sub` claim and is valid for
    `ACCESS_TOKEN_EXPIRE_MINUTES` minutes (default: 30).
    """
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(access_token=access_token, token_type="bearer")


#Protected routes

@app.get("/users/me", response_model=UserResponse)
def read_current_user(current_user: UserModel = Depends(get_current_user)):
    """
    Return the profile of the currently authenticated user.

    Requires a valid Bearer token in the Authorization header.
    """
    return current_user


@app.get("/users/me/status")
def user_status(current_user: UserModel = Depends(get_current_user)):
    """A lightweight endpoint to verify that a token is still valid."""
    return {"username": current_user.username, "active": current_user.is_active}


#Health check

@app.get("/health")
def health():
    """Simple liveness probe."""
    return {"status": "ok"}

#Entry point

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)