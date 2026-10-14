"""
Application configuration via pydantic-settings.

All settings are loaded from environment variables (with .env file fallback).
Secrets are NEVER logged, printed, or included in API responses.
"""

from __future__ import annotations

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Neo4jSettings(BaseSettings):
    """Neo4j bi-temporal graph database connection settings."""

    model_config = SettingsConfigDict(env_prefix="NEO4J_")

    uri: str = Field(
        default="bolt://localhost:7687",
        description="Neo4j Bolt protocol URI.",
    )
    username: str = Field(
        default="neo4j",
        description="Neo4j authentication username.",
    )
    password: SecretStr = Field(
        default=SecretStr(""),
        description="Neo4j authentication password. Never logged.",
    )
    database: str = Field(
        default="selfhealing",
        description="Neo4j database name for bi-temporal state graph.",
    )


class E2BSandboxSettings(BaseSettings):
    """E2B micro-sandbox execution settings."""

    model_config = SettingsConfigDict(env_prefix="E2B_")

    api_key: SecretStr = Field(
        default=SecretStr(""),
        description="E2B API key for sandbox provisioning. Never logged.",
    )
    sandbox_timeout_ms: int = Field(
        default=30000,
        ge=1000,
        le=300000,
        description="Maximum sandbox execution time in milliseconds.",
    )


class LLMSettings(BaseSettings):
    """LLM reasoning engine configuration."""

    model_config = SettingsConfigDict(env_prefix="LLM_")

    provider: str = Field(
        default="google",
        description="LLM provider identifier (google, openai, anthropic).",
    )
    model: str = Field(
        default="gemini-2.5-flash",
        description="Model identifier for the reasoning engine.",
    )
    api_key: SecretStr = Field(
        default=SecretStr(""),
        description="LLM API key. Never logged.",
    )
    max_context_tokens: int = Field(
        default=128000,
        ge=1000,
        description="Maximum context window size in tokens.",
    )
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
        description="Sampling temperature. Low values for deterministic SRE analysis.",
    )


class PreFilterSettings(BaseSettings):
    """Regex-first trace pre-filter settings (regex-vs-llm pattern)."""

    model_config = SettingsConfigDict(env_prefix="PREFILTER_", populate_by_name=True)

    context_budget_max_tokens: int = Field(
        default=32000,
        ge=1000,
        description="Hard ceiling on tokens forwarded to the LLM reasoning layer.",
        alias="CONTEXT_BUDGET_MAX_TOKENS",
    )
    compression_target: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description=(
            "Target compression ratio (filtered/raw). "
            "Values below 0.05 indicate aggressive filtering."
        ),
    )


class SlackSettings(BaseSettings):
    """Slack human-in-the-loop approval gate settings."""

    model_config = SettingsConfigDict(env_prefix="SLACK_")

    bot_token: SecretStr = Field(
        default=SecretStr(""),
        description="Slack Bot OAuth token for posting approval blocks.",
    )
    signing_secret: SecretStr = Field(
        default=SecretStr(""),
        description="Slack signing secret for request verification.",
    )
    approval_channel: str = Field(
        default="",
        description="Slack channel ID for posting approval requests.",
    )
    approval_ttl_seconds: int = Field(
        default=900,
        ge=60,
        le=86400,
        description="Time-to-live for approval requests before expiry (15m default).",
    )
    dev_mode: bool = Field(
        default=False,
        description="Explicit development bypass mode. Must be off by default.",
    )
    allowed_approver_roles: list[str] = Field(
        default_factory=lambda: ["sre-lead", "incident-commander", "admin"],
        description="Roles permitted to approve remediation actions.",
    )
    approver_role_mapping: dict[str, str] = Field(
        default_factory=dict,
        description="Map of Slack user IDs/usernames to authorized approver roles.",
    )


class MCPSettings(BaseSettings):
    """MCP client transport and retry settings."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    transport: str = Field(
        default="stdio",
        description="MCP transport type (stdio or http).",
    )
    heartbeat_interval_ms: int = Field(
        default=30000,
        ge=5000,
        description="Heartbeat ping interval in milliseconds.",
    )
    retry_max: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum retry attempts for failed tool calls.",
    )
    retry_backoff_base_ms: int = Field(
        default=1000,
        ge=100,
        description="Base delay for exponential backoff retries.",
    )


class MaskingSettings(BaseSettings):
    """Reversible identifier masking settings."""

    model_config = SettingsConfigDict(env_prefix="MASKING_")

    token_prefix: str = Field(
        default="MASKED_",
        description="Prefix for all masked identifier tokens.",
    )
    dictionary_persist: bool = Field(
        default=False,
        description=(
            "Whether to persist the masking dictionary across sessions. "
            "Must be False for production (security requirement)."
        ),
    )


class Settings(BaseSettings):
    """
    Root application settings.

    Aggregates all subsystem configurations into a single validated object.
    Loaded once at startup via the ``get_settings`` dependency.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── FastAPI Brain ──
    brain_host: str = Field(default="127.0.0.1", description="Bind address for the FastAPI server.")
    brain_port: int = Field(default=8000, ge=1, le=65535, description="Bind port.")
    brain_log_level: str = Field(
        default="info",
        description="Log level (debug, info, warning, error, critical).",
    )
    brain_cors_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins for the brain API.",
    )

    # ── Subsystem Settings ──
    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    e2b: E2BSandboxSettings = Field(default_factory=E2BSandboxSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    pre_filter: PreFilterSettings = Field(default_factory=PreFilterSettings)
    slack: SlackSettings = Field(default_factory=SlackSettings)
    mcp: MCPSettings = Field(default_factory=MCPSettings)
    masking: MaskingSettings = Field(default_factory=MaskingSettings)


# ─── Singleton accessor ──────────────────────────────────────────────

_settings: Settings | None = None


def get_settings() -> Settings:
    """
    Return the cached application settings singleton.

    This function is designed to be used as a FastAPI dependency::

        @router.get("/health")
        async def health(settings: Settings = Depends(get_settings)):
            ...
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset the settings singleton. Used in tests to inject overrides."""
    global _settings
    _settings = None
