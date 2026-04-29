from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Uygulama ayarları — .env dosyasından otomatik okunur."""

    # LLM
    gemini_api_key: str

    # Threat intelligence (opsiyonel)
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""

    # App
    app_env: str = "development"
    database_url: str = "sqlite:///./cloudguard.db"
    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Virgülle ayrılmış CORS origin'lerini liste olarak döndür."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


# Tek bir instance — tüm uygulama bunu kullanır
settings = Settings()
