from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from models import UserCreate, UserLogin, OTPRequest, OTPVerify
from database import get_user_collection, get_db
from kms import generate_encryption_key, store_user_key
from config import settings
import secrets
import pyotp
import smtplib
from email.mime.text import MIMEText

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def register_user(user: UserCreate, db=Depends(get_db)):
    user_collection = await get_user_collection(db)
    if await user_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    salt = secrets.token_hex(16)
    hashed_password = pwd_context.hash(user.password + salt + settings.pepper)
    encryption_key = generate_encryption_key()
    store_user_key(user.username, encryption_key)
    totp_secret = pyotp.random_base32()
    await user_collection.insert_one({
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password,
        "salt": salt,
        "failed_attempts": 0,
        "last_failed_attempt_time": None,
        "totp_secret": totp_secret,
        "two_factor_enabled": False
    })
    return {"message": "User registered successfully"}


async def login_user(user: UserLogin, db=Depends(get_db)):
    user_collection = await get_user_collection(db)
    db_user = await user_collection.find_one({"username": user.username})
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    # Check for too many failed attempts
    if db_user["failed_attempts"] >= 5:
        if db_user["last_failed_attempt_time"] is not None:
            time_since_last_attempt = (datetime.now(timezone.utc) - db_user["last_failed_attempt_time"]).seconds
            if time_since_last_attempt < 900:
                raise HTTPException(status_code=400, detail="Too many failed attempts. Try again later.")
        else:
            # If last_failed_attempt_time is None, treat it as no recent failed attempts
            await user_collection.update_one({"_id": db_user["_id"]}, {"$set": {"failed_attempts": 0}})

    if not pwd_context.verify(user.password + db_user["salt"] + settings.pepper, db_user["hashed_password"]):
        await user_collection.update_one({"_id": db_user["_id"]}, {"$inc": {"failed_attempts": 1}, "$set": {
            "last_failed_attempt_time": datetime.now(timezone.utc)}})
        raise HTTPException(status_code=400, detail="Invalid username or password")

    await user_collection.update_one({"_id": db_user["_id"]}, {"$set": {"failed_attempts": 0}})

    if db_user["two_factor_enabled"]:
        return {"message": "2FA required", "username": user.username}

    token = jwt.encode({"sub": user.username, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                       settings.jwt_secret, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_collection = await get_user_collection(db)
    user = await user_collection.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def send_otp(otp_request: OTPRequest, db=Depends(get_db)):
    user_collection = await get_user_collection(db)
    db_user = await user_collection.find_one({"username": otp_request.username})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    totp = pyotp.TOTP(db_user["totp_secret"])
    otp = totp.now()
    msg = MIMEText(f"Your OTP code is: {otp}")
    msg["Subject"] = "Your OTP Code"
    msg["From"] = settings.email_from
    msg["To"] = db_user["email"]
    try:
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port) as server:
            server.starttls()
            server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
    except smtplib.SMTPRecipientsRefused:
        raise HTTPException(status_code=400, detail=f"Failed to send OTP: Invalid email address {db_user['email']}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send OTP due to server error")
    return {"message": "OTP sent to your email"}


async def verify_otp(otp_verify: OTPVerify, db=Depends(get_db)):
    user_collection = await get_user_collection(db)
    db_user = await user_collection.find_one({"username": otp_verify.username})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    totp = pyotp.TOTP(db_user["totp_secret"])
    if not totp.verify(otp_verify.otp, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Enable two-factor authentication after successful OTP verification
    await user_collection.update_one({"_id": db_user["_id"]}, {"$set": {"two_factor_enabled": True}})

    token = jwt.encode({"sub": otp_verify.username, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                       settings.jwt_secret, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}