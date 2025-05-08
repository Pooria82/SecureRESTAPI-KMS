from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    mongodb_url: str = "mongodb://localhost:27017"
    db_name: str = "secure_api"
    jwt_secret: str
    pepper: str
    vault_url: str = "http://localhost:8200"
    vault_token: str
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    email_from: str

    class Config:
        env_file = ".env"

settings = Settings()