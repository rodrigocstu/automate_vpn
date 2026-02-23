from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Ansible PAN-OS Automation"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "CHANGE_ME_PER_ITIL_SECURITY_PRACTICES"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # DATABASE
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "ansible_db"
    
    # ANALYTICS / LOGS
    LOG_LEVEL: str = "INFO"
    
    # CELERY / REDIS
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # ANSIBLE
    ANSIBLE_DATA_DIR: str = "/data/ansible"

    class Config:
        env_file = ".env"

settings = Settings()
