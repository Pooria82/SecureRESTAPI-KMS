from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from models import UserCreate, UserLogin, SensitiveDataCreate, SensitiveDataResponse, SensitiveDataUpdate, OTPRequest, OTPVerify
from auth import register_user, login_user, get_current_user, send_otp, verify_otp
from kms import encrypt_data, decrypt_data, get_user_key, client, get_master_key, generate_new_master_key, re_encrypt_user_key
from database import get_db, get_sensitive_data_collection, get_user_collection
from bson import ObjectId
import re
from typing import List

app = FastAPI(
    title="Secure API",
    description="API for user authentication, sensitive data management, and key rotation with Vault integration.",
    version="1.0.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@app.post("/register", summary="Register a new user")
async def register(user: UserCreate, db=Depends(get_db)):
    return await register_user(user, db)

@app.post("/login", summary="Login and get access token")
async def login(user: UserLogin, db=Depends(get_db)):
    return await login_user(user, db)

@app.post("/send-otp", summary="Send OTP for two-factor authentication")
async def send_otp_route(otp_request: OTPRequest, db=Depends(get_db)):
    return await send_otp(otp_request, db)

@app.post("/verify-otp", summary="Verify OTP and get access token")
async def verify_otp_route(otp_verify: OTPVerify, db=Depends(get_db)):
    return await verify_otp(otp_verify, db)

@app.post("/sensitive-data", response_model=SensitiveDataResponse, summary="Store encrypted sensitive data")
async def store_sensitive_data(data: SensitiveDataCreate, current_user=Depends(get_current_user), db=Depends(get_db)):
    if data.data_type == "card_number" and not re.match(r'^\d{16}$', data.value):
        raise HTTPException(status_code=400, detail="Invalid card number")
    try:
        encryption_key = get_user_key(current_user["username"])
    except ValueError as e:
        raise HTTPException(status_code=500, detail="Encryption key not found for user")
    encrypted_value = encrypt_data(data.value, encryption_key)
    sensitive_data = {
        "user_id": current_user["_id"],
        "data_type": data.data_type,
        "encrypted_value": encrypted_value.hex()
    }
    collection = await get_sensitive_data_collection(db)
    result = await collection.insert_one(sensitive_data)
    return SensitiveDataResponse(id=str(result.inserted_id), data_type=data.data_type, value=data.value)

@app.get("/sensitive-data", response_model=List[SensitiveDataResponse], summary="Retrieve all sensitive data for the user")
async def get_sensitive_data(current_user=Depends(get_current_user), db=Depends(get_db)):
    try:
        encryption_key = get_user_key(current_user["username"])
    except ValueError as e:
        raise HTTPException(status_code=500, detail="Encryption key not found for user")
    collection = await get_sensitive_data_collection(db)
    sensitive_data_list = await collection.find({"user_id": current_user["_id"]}).to_list(None)
    decrypted_data = []
    for data in sensitive_data_list:
        try:
            decrypted_value = decrypt_data(bytes.fromhex(data["encrypted_value"]), encryption_key)
            decrypted_data.append(SensitiveDataResponse(id=str(data["_id"]), data_type=data["data_type"], value=decrypted_value))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to decrypt data: {str(e)}")
    return decrypted_data

@app.put("/sensitive-data/{data_id}", response_model=SensitiveDataResponse, summary="Update existing sensitive data")
async def update_sensitive_data(data_id: str, data: SensitiveDataUpdate, current_user=Depends(get_current_user), db=Depends(get_db)):
    if data.data_type == "card_number" and not re.match(r'^\d{16}$', data.value):
        raise HTTPException(status_code=400, detail="Invalid card number")
    try:
        encryption_key = get_user_key(current_user["username"])
    except ValueError as e:
        raise HTTPException(status_code=500, detail="Encryption key not found for user")
    encrypted_value = encrypt_data(data.value, encryption_key)
    collection = await get_sensitive_data_collection(db)
    result = await collection.update_one(
        {"_id": ObjectId(data_id), "user_id": current_user["_id"]},
        {"$set": {"data_type": data.data_type, "encrypted_value": encrypted_value.hex()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Data not found or not authorized")
    return SensitiveDataResponse(id=data_id, data_type=data.data_type, value=data.value)

@app.delete("/sensitive-data/{data_id}", summary="Delete sensitive data")
async def delete_sensitive_data(data_id: str, current_user=Depends(get_current_user), db=Depends(get_db)):
    collection = await get_sensitive_data_collection(db)
    result = await collection.delete_one({"_id": ObjectId(data_id), "user_id": current_user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Data not found or not authorized")
    return {"message": "Data deleted successfully"}

@app.post("/rotate-master-key", summary="Rotate the master encryption key in Vault")
async def rotate_key(current_user=Depends(get_current_user), db=Depends(get_db)):
    old_master_key = get_master_key()
    new_master_key = generate_new_master_key()
    user_collection = await get_user_collection(db)
    users = await user_collection.find().to_list(None)
    for user in users:
        username = user["username"]
        re_encrypt_user_key(username, old_master_key, new_master_key)
    client.secrets.kv.v2.create_or_update_secret(path='master_key', secret={'key': new_master_key.hex()})
    return {"message": "Master key rotated successfully"}