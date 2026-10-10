from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from typing import List, Optional, Dict

MODEL_DIR = Path(__file__).resolve().parents[2] / "models"

class Settings(BaseSettings):
    APP_NAME: str = 'Aegis AI Firewall'
    VERSION: str = '1.0.0'
    DEBUG: bool = False
    ENVIRONMENT: str = "development"
    COOKIE_SECURE: bool = False
    SESSION_TTL_SECONDS: int = 3600
    MAX_SESSIONS: int = 2000
    MAX_SESSION_EVENTS: int = 100
    REQUIRE_ML_MODELS: bool = False
    UPSTREAM_ALLOWED_ORIGINS: List[str] = [
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://api.openai.com",
        "https://api.anthropic.com",
        "https://api.groq.com",
    ]
    PROTECTED_OUTPUT_VALUES: List[str] = []
    TOOL_ENDPOINTS: Dict[str, str] = {}
    ALLOWED_TOOLS: List[str] = ["search", "calculate", "calculate_sum"]
    API_KEY: str = "secret-key-change-me"
    # Hackathon/local dashboard credentials. Production startup rejects these defaults.
    DASHBOARD_USERNAME: str = "admin"
    DASHBOARD_PASSWORD: str = "admin123"
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegis_firewall.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    MAX_CONTENT_LENGTH: int = 10 * 1024 * 1024
    MAX_FILE_SIZE: int = 50 * 1024 * 1024
    REQUEST_TIMEOUT: int = 30
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60

    WOLF_DEFENDER_MODEL_PATH: Optional[str] = str(MODEL_DIR / "wolf_defender")
    DEBERTA_MODEL_PATH: Optional[str] = str(MODEL_DIR / "deberta-v3-base-prompt-injection-v2")
    LAYA_MODEL_PATH: Optional[str] = str(MODEL_DIR / "laya" / "multilingual")
    LAYA_ENGLISH_MODEL_PATH: Optional[str] = str(MODEL_DIR / "laya" / "english")
    OPEN_JEV_MODEL_PATH: Optional[str] = str(MODEL_DIR / "open_jev")
    LIGHTGBM_MODEL_PATH: Optional[str] = str(MODEL_DIR / "lightgbm" / "model.txt")

    RISK_LOW_THRESHOLD: float = 0.19
    RISK_MEDIUM_THRESHOLD: float = 0.49
    RISK_HIGH_THRESHOLD: float = 0.79

    LLM_PROVIDER: str = "openai"
    LLM_BASE_URL: Optional[str] = None
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gpt-4o"

    ENABLE_RATE_LIMITING: bool = True
    ENABLE_API_AUTH: bool = True
    ALLOWED_FILE_TYPES: List[str] = ["pdf", "docx", "html", "txt", "md", "json", "xml", "png", "jpg", "jpeg"]
    OUTPUT_SECURITY_MODE: str = "FULL_BUFFER"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
