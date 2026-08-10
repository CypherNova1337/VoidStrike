"""Runtime configuration for VoidStrike."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class HttpConfig:
    timeout: float = 15.0
    max_concurrency: int = 8
    requests_per_second: float = 10.0
    retries: int = 2
    verify_tls: bool = True
    proxy: str | None = None
    user_agent: str = "VoidStrike/1.0 (authorized-security-testing)"
    default_headers: dict = field(default_factory=dict)


@dataclass
class AIConfig:
    """LLM provider configuration.

    Provider-agnostic on purpose: point it at any OpenAI-compatible or
    messages-style HTTP endpoint. Credentials are read from the environment
    so they never live in a committed config file.
    """

    enabled: bool = True
    provider: str = "generic"  # "generic" | "openai_compatible" | "messages"
    base_url: str = os.environ.get("VOIDSTRIKE_LLM_BASE_URL", "")
    model: str = os.environ.get("VOIDSTRIKE_LLM_MODEL", "")
    api_key_env: str = "VOIDSTRIKE_LLM_API_KEY"
    temperature: float = 0.4
    max_tokens: int = 1024
    request_timeout: float = 60.0

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env)


@dataclass
class OOBConfig:
    """Out-of-band (OAST) interaction settings."""

    enabled: bool = False
    # A callback domain you control (e.g. an Interactsh/collaborator domain).
    collaborator_domain: str = os.environ.get("VOIDSTRIKE_OOB_DOMAIN", "")
    # Optional local HTTP listener for callbacks when you control the network path.
    listener_host: str = "0.0.0.0"
    listener_port: int = 0  # 0 == disabled
    poll_url: str = ""  # optional polling endpoint for a hosted collaborator


@dataclass
class Config:
    http: HttpConfig = field(default_factory=HttpConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    oob: OOBConfig = field(default_factory=OOBConfig)
    output_dir: str = "voidstrike-results"
    use_color: bool = True
    verbose: bool = False
    # Safety rail: hard cap on total payloads sent per target per module.
    max_payloads_per_module: int = 60
