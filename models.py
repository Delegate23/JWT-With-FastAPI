from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy.sql import func
from pydantic import BaseModel, EmailStr
from typing import Optional
from database import Base


#SQLAlchemy ORM Model 

class UserModel(Base):
    """Database table for users."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


#Pydantic Schemas

class UserCreate(BaseModel):
    """Schema for creating a new user."""
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Schema returned to the client (never exposes password)."""
    id: int
    username: str
    email: str
    is_active: bool

    class Config:
        from_attributes = True  # Enables ORM mode


class TokenData(BaseModel):
    """Payload extracted from a decoded JWT."""
    username: Optional[str] = None


class Token(BaseModel):
    """Response schema for a successful login."""
    access_token: str
    token_type: str


class LoginRequest(BaseModel):
    """Schema for login credentials."""
    username: str
    password: str