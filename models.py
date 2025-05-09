from pydantic import BaseModel, field_validator, EmailStr
import re

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class SensitiveDataCreate(BaseModel):
    data_type: str
    value: str

class SensitiveDataResponse(BaseModel):
    id: str
    data_type: str
    value: str

class SensitiveDataUpdate(BaseModel):
    data_type: str
    value: str

class OTPRequest(BaseModel):
    username: str

class OTPVerify(BaseModel):
    username: str
    otp: str