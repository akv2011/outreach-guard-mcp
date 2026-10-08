import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass

DEMO_DOMAINS = "example.com,example.org,example.net"


def _csv(value: str) -> frozenset[str]:
    return frozenset(v.strip().lower() for v in value.split(",") if v.strip())


@dataclass(frozen=True)
class Settings:
    base_url: str
    google_client_id: str
    google_client_secret: str
    jwt_signing_key: str
    session_secret: str
    instantly_api_key: str
    gemini_api_key: str
    gemini_model: str
    redis_url: str
    allowed_emails: frozenset[str]
    recipient_domains: frozenset[str]
    daily_send_cap: int
    rate_limit_per_min: int
    chat_limit_per_day: int
    blocked_domains: frozenset[str] = frozenset()
    require_approval: bool = True

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Settings":
        instantly_api_key = env.get("INSTANTLY_API_KEY", "")
        # Demo mode sends nothing, so it opens the seeded domains; live mode denies every send until configured.
        default_domains = "" if instantly_api_key else DEMO_DOMAINS
        return cls(
            base_url=env.get("BASE_URL", "http://localhost:8000").rstrip("/"),
            google_client_id=env.get("GOOGLE_CLIENT_ID", ""),
            google_client_secret=env.get("GOOGLE_CLIENT_SECRET", ""),
            jwt_signing_key=env.get("JWT_SIGNING_KEY", ""),
            session_secret=env.get("SESSION_SECRET", ""),
            instantly_api_key=instantly_api_key,
            gemini_api_key=env.get("GEMINI_API_KEY", ""),
            gemini_model=env.get("GEMINI_MODEL", "gemini-3.8-flash"),
            redis_url=env.get("REDIS_URL", ""),
            allowed_emails=_csv(env.get("ALLOWED_EMAILS", "")),
            recipient_domains=_csv(env.get("RECIPIENT_DOMAINS", default_domains)),
            daily_send_cap=int(env.get("DAILY_SEND_CAP", "5")),
            rate_limit_per_min=int(env.get("RATE_LIMIT_PER_MIN", "5")),
            chat_limit_per_day=int(env.get("CHAT_LIMIT_PER_DAY", "10")),
        )

    @property
    def mode(self) -> str:
        return "live" if self.instantly_api_key else "demo"

    def derived_key(self, purpose: str) -> bytes:
        if len(self.session_secret) < 32:
            raise RuntimeError("SESSION_SECRET must be at least 32 characters")
        return hashlib.sha256(f"{purpose}:{self.session_secret}".encode()).digest()
