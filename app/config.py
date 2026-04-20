import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    vt_api_key: str | None = os.getenv("VT_API_KEY")
    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY")
    urlhaus_auth_key: str | None = os.getenv("URLHAUS_AUTH_KEY")
    otx_api_key: str | None = os.getenv("OTX_API_KEY")
    app_env: str = os.getenv("APP_ENV", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    model_name: str = os.getenv("MODEL_NAME", "rule_based_v8")


settings = Settings()