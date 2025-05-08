from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

async def get_db():
    client = AsyncIOMotorClient(settings.mongodb_url)
    db = client[settings.db_name]
    return db

async def get_user_collection(db):
    return db["users"]

async def get_sensitive_data_collection(db):
    return db["sensitive_data"]