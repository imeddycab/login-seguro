from pydantic import BaseModel, EmailStr, Field, validator
import re
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2, max_length=100)
    
    @validator('password')
    def validate_password(cls, v):
        """Validación de contraseña segura"""
        if not re.search(r'[A-Z]', v):
            raise ValueError('La contraseña debe tener al menos una mayúscula')
        if not re.search(r'[a-z]', v):
            raise ValueError('La contraseña debe tener al menos una minúscula')
        if not re.search(r'\d', v):
            raise ValueError('La contraseña debe tener al menos un número')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('La contraseña debe tener al menos un carácter especial')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: str
    full_name: str
    is_active: bool
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None