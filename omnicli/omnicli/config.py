"""
Configuration manager for OmniCLI.
Handles provider definitions, API keys, endpoints, and persistent settings.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

def _default_config_dir() -> Path:
    """OmniCLI's own config root — standalone, no suite layout assumed.

    OMNICLI_CONFIG_DIR wins, then XDG_CONFIG_HOME/omnicli, then the
    conventional ~/.config/omnicli. Resolved at construction time so
    hosts/tests can redirect via environment.
    """
    explicit = os.environ.get("OMNICLI_CONFIG_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg:
        return Path(xdg).expanduser() / "omnicli"
    return Path.home() / ".config" / "omnicli"


CONFIG_DIR = _default_config_dir()
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history"
# Documented shared-suite store (Oracle/Scan4Me/OmniCLI trio). OmniCLI
# reads it as ONE named source; OMNICLI_KEYS_FILE / TRIO_KEYS_FILE env
# vars and OmniCLI's own keys.env take precedence. No other file is
# scavenged — integration is explicit, never layout guessing.
TRIO_KEYS_FILE = Path.home() / ".config" / "trio" / "keys.env"

# Model family keywords used by `omni scan` to classify discovered models.
# Order matters: first match wins. Extend here to recognise new families.
MODEL_FAMILY_KEYWORDS: list = [
    ("anthropic",  ["claude"]),
    ("openai",     ["gpt-", "o1-", "o3-", "o4-"]),
    ("meta",       ["llama"]),
    ("google",     ["gemini", "gemma"]),
    ("mistral",    ["mistral", "mixtral"]),
    ("qwen",       ["qwen"]),
    ("deepseek",   ["deepseek"]),
    ("xai",        ["grok"]),
    ("minimax",    ["minimax"]),
    ("nvidia",     ["nemotron", "nv-"]),
    ("cohere",     ["command"]),
    ("databricks", ["dbrx"]),
    ("microsoft",  ["phi-", "phi3", "wizardlm"]),
    ("glm",        ["glm"]),
    ("01ai",       ["yi-"]),
]

DEFAULT_PROVIDERS = {
    "openrouter": {
        "name": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "env_key": "OPENROUTER_API_KEY",
        "default_model": "google/gemini-2.5-flash",
        "description": "Multi-model router with 300+ models",
        "requires_auth_for_models": False,
        # Populated by `omni scan` — not hardcoded.
        "fallback_models": [],
        "verification_panel": [],
    },
    "nvidia": {
        "name": "NVIDIA Build / NIM",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "env_key": "NVIDIA_API_KEY",
        "alt_env_keys": ["NVAPI_KEY"],
        "default_model": "meta/llama-3.2-11b-vision-instruct",
        "description": "NVIDIA NIM high-throughput inference endpoints",
        "requires_auth_for_models": False,
        "fallback_models": [],
        "verification_panel": [],
    },
    "cloudflare": {
        "name": "Cloudflare Workers AI",
        "base_url_template": "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
        "base_url": "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
        "env_key": "CLOUDFLARE_API_TOKEN",
        "alt_env_keys": ["CLOUDFLARE_API_KEY"],
        "account_id_env": "CLOUDFLARE_ACCOUNT_ID",
        "default_model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        "description": "Cloudflare Workers AI serverless inference",
        "requires_auth_for_models": True,
        "fallback_models": [],
        "verification_panel": [],
    },
    "bynara": {
        "name": "Bynara Router",
        "base_url": "https://router.bynara.id/v1",
        "env_key": "BYNARA_API_KEY",
        "default_model": "agnes-2.5-flash",
        "description": "Bynara AI Gateway & Router (7M tokens/day)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "agnes-3-flash",
            "deepseek-v4-flash-alibaba",
        ],
        "verification_panel": [
            {"model": "agnes-2.5-flash", "family": "google"},
        ],
    },
    "apinex": {
        "name": "Apinex Router",
        "base_url": "https://api.apinex.bond/v1",
        "env_key": "APINEX_API_KEY",
        "default_model": "deepseek-v4-flash",
        "description": "Apinex AI Model Proxy (10M tokens/24h)",
        "requires_auth_for_models": True,
        "fallback_models": [],
        "verification_panel": [],
    },
    "xkiro": {
        "name": "XKiro Router",
        "base_url": "https://api.xkiro.com/v1",
        "env_key": "XKIRO_API_KEY",
        "default_model": "qwen/qwen3.6-27b:free",
        "description": "XKiro Model Router & Gateway (1M/day, 30M pool)",
        "requires_auth_for_models": False,
        "fallback_models": [
            "qwen/qwen3.7-flash:free",
            "inclusionai/ling-3.0-flash-sante:free",
        ],
        "verification_panel": [
            {"model": "qwen/qwen3.6-27b:free", "family": "qwen"},
        ],
    },
    "dahl": {
        "name": "Dahl Inference",
        "base_url": "https://inference.dahl.global/v1",
        "env_key": "DAHL_API_KEY",
        "default_model": "zai-org/GLM-5.3-Flash",
        "description": "Dahl Global high-capacity inference gateway (100M tokens)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "deepseek-ai/DeepSeek-V4-Flash-0731",
            "MiniMaxAI/MiniMax-M2.7",
        ],
        "verification_panel": [
            {"model": "zai-org/GLM-5.3-Flash", "family": "glm"},
            {"model": "deepseek-ai/DeepSeek-V4-Flash-0731", "family": "deepseek"},
        ],
    },
    "llm7": {
        "name": "LLM7 Gateway",
        "base_url": "https://api.llm7.io/v1",
        "env_key": "LLM7_API_KEY",
        "default_model": "default",
        "description": "LLM7 multi-provider gateway (free tier selectors)",
        "requires_auth_for_models": False,
        "fallback_models": [
            "fast",
        ],
        "verification_panel": [
            {"model": "default", "family": "other"},
        ],
    },
    "groq": {
        "name": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "env_key": "GROQ_API_KEY",
        "default_model": "openai/gpt-oss-120b",
        "description": "Groq ultra-fast LPU inference endpoints",
        "requires_auth_for_models": True,
        "fallback_models": [
            "openai/gpt-oss-20b",
            "qwen/qwen3.8-27b",
        ],
        "verification_panel": [
            {"model": "openai/gpt-oss-120b", "family": "openai"},
            {"model": "qwen/qwen3.8-27b", "family": "qwen"},
        ],
    },
    "monkeycode": {
        "name": "MonkeyCode AI",
        "base_url": "https://api.monkeycode-ai.net/v1",
        "env_key": "MONKEYCODE_API_KEY",
        "default_model": "monkeycode-basic/qwen3.8-flash",
        "description": "Chaitin MonkeyCode AI Platform (10M daily tokens, Google OAuth alexander.sorrell.it)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "monkeycode-basic/qwen3.8-flash",
            "monkeycode-basic/deepseek-flash",
            "monkeycode-pro/glm-5.2",
        ],
        "verification_panel": [
            {"model": "monkeycode-basic/qwen3.8-flash", "family": "qwen"},
            {"model": "monkeycode-basic/deepseek-flash", "family": "deepseek"},
        ],
    },
    "freebuff": {
        "name": "FreeBuff",
        "base_url": "https://freebuff.com/api/v1",
        "env_key": "FREEBUFF_API_KEY",
        "default_model": "default",
        "description": "FreeBuff AI Model Gateway",
        "requires_auth_for_models": True,
        "fallback_models": [],
        "verification_panel": [],
    },
    "freeai": {
        "name": "FreeAI",
        "base_url": "https://api.free.ai/v1",
        "env_key": "FREEAI_API_KEY",
        "default_model": "default",
        "description": "FreeAI Chat Gateway",
        "requires_auth_for_models": True,
        "fallback_models": [],
        "verification_panel": [],
    },
    "deepinfra": {
        "name": "DeepInfra",
        "base_url": "https://api.deepinfra.com/v1/openai",
        "env_key": "DEEPINFRA_API_KEY",
        "default_model": "meta-llama/Meta-Llama-3.1-405B-Instruct",
        "description": "DeepInfra high-performance inference (405B, 70B, 8B models)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "meta-llama/Meta-Llama-3.1-70B-Instruct",
            "meta-llama/Meta-Llama-3.1-8B-Instruct",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
        ],
        "verification_panel": [
            {"model": "meta-llama/Meta-Llama-3.1-405B-Instruct", "family": "meta"},
            {"model": "meta-llama/Meta-Llama-3.1-70B-Instruct", "family": "meta"},
        ],
    },
    "pollinations": {
        "name": "Pollinations",
        "base_url": "https://text.pollinations.ai/openai/v1",
        "env_key": "POLLINATIONS_API_KEY",
        "default_model": "gpt-4o-mini",
        "description": "Pollinations.AI - Free/Open AI models (gpt-4o, gpt-4o-mini, llama-3.1-405b, flux, etc.)",
        "requires_auth_for_models": False,
        "fallback_models": [
            "gpt-4o-mini",
            "gpt-4o",
            "llama-3.1-405b",
        ],
        "verification_panel": [
            {"model": "gpt-4o-mini", "family": "openai"},
            {"model": "gpt-4o", "family": "openai"},
        ],
    },
    # ── 2026-10 expansion: operator-supplied gateways ─────────────────────
    "ovhcloud": {
        "name": "OVHcloud AI Endpoints",
        "base_url": "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
        "env_key": "OVH_AI_ENDPOINTS_ACCESS_TOKEN",
        "key_required": False,
        "default_model": "Meta-Llama-3_3-70B-Instruct",
        "description": "OVHcloud AI Endpoints OpenAI-compatible gateway (22 models, public tier; token optional)",
        "requires_auth_for_models": False,
        "fallback_models": [
            "Qwen3.8-27B",
            "gpt-oss-120b",
            "Mistral-Small-3.2-24B-Instruct-2506",
        ],
        "verification_panel": [
            {"model": "Meta-Llama-3_3-70B-Instruct", "family": "meta"},
            {"model": "Qwen3.8-27B", "family": "qwen"},
        ],
    },
    "aionlabs": {
        "name": "AionLabs",
        "base_url": "https://api.aionlabs.ai/v1",
        "env_key": "AIONLABS_API_KEY",
        "default_model": "aion-labs/aion-3.5",
        "description": "AionLabs Aion models (Cloudflare-fronted: needs a browser User-Agent)",
        "requires_auth_for_models": True,
        "extra_headers": {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        },
        "fallback_models": [
            "aion-labs/aion-3.5-mini",
            "aion-labs/aion-3.0",
        ],
        "verification_panel": [
            {"model": "aion-labs/aion-3.5", "family": "other"},
        ],
    },
    "cohere": {
        "name": "Cohere",
        "base_url": "https://api.cohere.com/compatibility/v1",
        "env_key": "COHERE_API_KEY",
        "default_model": "command-a-plus-05-2026",
        "description": "Cohere Command models via the OpenAI-compatible endpoint (native /v2 is not OpenAI-shaped)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "command-a-03-2025",
            "command-r-plus-08-2024",
            "command-r7b-12-2024",
        ],
        "verification_panel": [
            {"model": "command-a-plus-05-2026", "family": "cohere"},
            {"model": "command-a-03-2025", "family": "cohere"},
        ],
    },
    "gonkabroker": {
        "name": "GonkaBroker Proxy",
        "base_url": "https://proxy.gonkabroker.com/v1",
        "env_key": "GONKABROKER_API_KEY",
        "default_model": "zai-org/GLM-5.3-Flash",
        "description": "GonkaBroker OpenAI-compatible proxy (GLM / DeepSeek / MiniMax)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "deepseek-ai/DeepSeek-V4-Flash-0731",
            "MiniMaxAI/MiniMax-M2.7",
        ],
        "verification_panel": [
            {"model": "zai-org/GLM-5.3-Flash", "family": "glm"},
            {"model": "deepseek-ai/DeepSeek-V4-Flash-0731", "family": "deepseek"},
        ],
    },
    "kilo": {
        "name": "Kilo AI Gateway",
        "base_url": "https://api.kilo.ai/api/gateway",
        "env_key": "KILO_API_KEY",
        "default_model": "kilo-auto/free",
        "description": "Kilo AI gateway (free auto-router tier; paid models need credits)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "deepseek/deepseek-v4.1-flash",
            "z-ai/glm-5.3-flash",
            "nvidia/nemotron-3.5-super-vl:free",
        ],
        "verification_panel": [
            {"model": "kilo-auto/free", "family": "other"},
        ],
    },
    "modelscope": {
        "name": "ModelScope",
        "base_url": "https://api-inference.modelscope.cn/v1",
        "env_key": "MODELSCOPE_API_KEY",
        "default_model": "deepseek-ai/DeepSeek-V4.1-Flash",
        "description": "Alibaba ModelScope inference (requires an Alibaba Cloud account binding)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "deepseek-ai/DeepSeek-V4-Pro",
            "MiniMax/MiniMax-M3",
            "mistralai/Mistral-Large-Instruct-2407",
        ],
        "verification_panel": [
            {"model": "deepseek-ai/DeepSeek-V4.1-Flash", "family": "deepseek"},
            {"model": "MiniMax/MiniMax-M3", "family": "minimax"},
        ],
    },
    "airforce": {
        "name": "AI Airforce",
        "base_url": "https://api.airforce/v1",
        "env_key": "AIRFORCE_API_KEY",
        "default_model": "gemma3-270m:free",
        "description": "AI Airforce multi-model gateway (free tier + paid subscription; browser UA required)",
        "requires_auth_for_models": True,
        "extra_headers": {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        },
        "fallback_models": [
            "gpt-oss-20b",
            "llama-instant",
            "mistral-large-4",
        ],
        "verification_panel": [
            {"model": "gemma3-270m:free", "family": "google"},
        ],
    },
    "orcarouter": {
        "name": "OrcaRouter",
        "base_url": "https://api.orcarouter.ai/v1",
        "env_key": "ORCAROUTER_API_KEY",
        "default_model": "orcarouter/free",
        "description": "OrcaRouter multi-model router (free tier; wallet billing for paid models)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "deepseek/deepseek-v4.1-flash-free",
            "orcarouter/auto",
            "google/gemini-3.5-flash",
        ],
        "verification_panel": [
            {"model": "orcarouter/free", "family": "other"},
        ],
    },
    "tokenrouter": {
        "name": "TokenRouter",
        "base_url": "https://api.tokenrouter.com/v1",
        "env_key": "TOKENROUTER_API_KEY",
        "default_model": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
        "description": "TokenRouter multi-model gateway (free tier + gift balance; browser UA required)",
        "requires_auth_for_models": True,
        "extra_headers": {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        },
        "fallback_models": [
            "qwen/qwen3.5-9b",
            "deepseek/deepseek-v4-pro",
            "google/gemini-3.5-flash-lite",
        ],
        "verification_panel": [
            {"model": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free", "family": "nvidia"},
        ],
    },
    "haimaker": {
        "name": "Haimaker",
        "base_url": "https://api.haimaker.ai/v1",
        "env_key": "HAIMAKER_API_KEY",
        "default_model": "auto",
        "description": "Haimaker LiteLLM gateway (keys unlock after $10 verified credits)",
        "requires_auth_for_models": True,
        "fallback_models": [],
        "verification_panel": [],
    },
    "publicai": {
        "name": "PublicAI",
        "base_url": "https://api.publicai.co/v1",
        "env_key": "PUBLICAI_API_KEY",
        "default_model": "swiss-ai/apertus-8b-instruct",
        "description": "PublicAI sovereign-model inference (Apertus, SEA-LION, ALIA)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "swiss-ai/apertus-70b-instruct",
            "aisingapore/Qwen-SEA-LION-v4-32B-IT",
            "BSC-LT/ALIA-40b-instruct",
        ],
        "verification_panel": [
            {"model": "swiss-ai/apertus-8b-instruct", "family": "other"},
            {"model": "aisingapore/Qwen-SEA-LION-v4-32B-IT", "family": "qwen"},
        ],
    },
    "cometapi": {
        "name": "CometAPI",
        "base_url": "https://api.cometapi.com/v1",
        "env_key": "COMETAPI_API_KEY",
        "default_model": "auto",
        "description": "CometAPI aggregator (OpenAI/Anthropic/Google/DeepSeek, 500+ models)",
        "requires_auth_for_models": True,
        # The `auto` router rejects any explicit temperature (400
        # unsupported_value); omit it so the default applies.
        "supports_temperature": False,
        "fallback_models": [
            "gpt-4o-mini",
            "deepseek-chat",
            "gemini-3.5-flash",
        ],
        "verification_panel": [
            {"model": "gpt-4o-mini", "family": "openai"},
            {"model": "deepseek-chat", "family": "deepseek"},
        ],
    },
    "nanogpt": {
        "name": "NanoGPT",
        "base_url": "https://nano-gpt.com/api/v1",
        "env_key": "NANOGPT_API_KEY",
        "default_model": "openai/gpt-4o-mini",
        "description": "NanoGPT pay-per-use gateway (OpenAI-compatible, 600+ models)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "particle-ai/particle-1",
            "openai/gpt-5.6-luna",
            "google/gemini-3.5-flash",
        ],
        "verification_panel": [
            {"model": "openai/gpt-4o-mini", "family": "openai"},
        ],
    },
    "requesty": {
        "name": "Requesty Router",
        "base_url": "https://router.requesty.ai/v1",
        "env_key": "REQUESTY_API_KEY",
        "default_model": "openai/gpt-4o-mini",
        "description": "Requesty multi-provider router (800+ models, wallet billing)",
        "requires_auth_for_models": True,
        "fallback_models": [
            "google/gemini-3.5-flash",
            "openai/gpt-5.4-nano",
        ],
        "verification_panel": [
            {"model": "openai/gpt-4o-mini", "family": "openai"},
            {"model": "google/gemini-3.5-flash", "family": "google"},
        ],
    },
}

# Per-provider memory (context injection + optional history). File entries are
# relative to "dir" or absolute, so each API can layer several memory sources.
DEFAULT_MEMORY = {
    "enabled": True,
    "dir": str(CONFIG_DIR / "memory"),
    "global": [],
    "providers": {},
    "history": {"enabled": False, "max_turns": 40},
}

# Heartbeat: built-in health checks (status) + an optional user task file.
DEFAULT_HEARTBEAT = {
    "canary": False,
    "status_file": str(CONFIG_DIR / "heartbeat.json"),
    "tasks_file": str(CONFIG_DIR / "heartbeat_tasks.json"),
}


class ConfigManager:
    """Provider/key settings rooted at a caller-chosen directory.

    config_dir defaults via _default_config_dir() (standalone CLI use).
    Library consumers pass their own root (e.g. a tmp dir or the host
    app's config dir) so importing and driving OmniCLI never touches
    the user's home.
    """

    def __init__(self, config_dir: Optional[Any] = None) -> None:
        self.config_dir = Path(config_dir) if config_dir else _default_config_dir()
        self.config_file = self.config_dir / "config.json"
        self.history_file = self.config_dir / "history"
        self._ensure_dir()
        self.data: Dict[str, Any] = self._load()

    def _ensure_dir(self) -> None:
        # S9: the dir holds key material — create/heal it private (0700),
        # never umask-default traversable.
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if os.stat(self.config_dir).st_mode & 0o077:
                os.chmod(self.config_dir, 0o700)
        except OSError:
            pass
        if not self.history_file.exists():
            self.history_file.touch(mode=0o600, exist_ok=True)

    def _load(self) -> Dict[str, Any]:
        if self.config_file.exists():
            # Self-heal installs created before atomic 0600 saves: a config
            # holding API keys must never stay group/world-readable merely
            # because no write happens this run.
            try:
                if os.stat(self.config_file).st_mode & 0o077:
                    os.chmod(self.config_file, 0o600)
            except OSError:
                pass
        def _localized(block_name: str) -> dict:
            # Path-bearing defaults are rooted at THIS manager's config
            # dir, never baked from import-time HOME (standalone law).
            block = copy.deepcopy(
                DEFAULT_MEMORY if block_name == "memory" else DEFAULT_HEARTBEAT
            )
            if block_name == "memory":
                block["dir"] = str(self.config_dir / "memory")
            else:
                block["status_file"] = str(self.config_dir / "heartbeat.json")
                block["tasks_file"] = str(self.config_dir / "heartbeat_tasks.json")
            return block

        if not self.config_file.exists():
            initial_data = {
                "default_provider": "groq",
                "providers": copy.deepcopy(DEFAULT_PROVIDERS),
                "keys": {},
                "cloudflare_account_id": "",
                "system_prompt": "You are a helpful, brilliant, concise AI assistant.",
                "temperature": 0.7,
                "timeout": 60,
                "memory": _localized("memory"),
                "heartbeat": _localized("heartbeat"),
            }
            self._save(initial_data)
            return initial_data

        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Ensure all default providers exist
            if "providers" not in data:
                data["providers"] = {}
            for k, v in DEFAULT_PROVIDERS.items():
                if k not in data["providers"]:
                    data["providers"][k] = copy.deepcopy(v)
            if "keys" not in data:
                data["keys"] = {}
            # Migrate older configs: add memory/heartbeat blocks if absent.
            changed = False
            if "memory" not in data:
                data["memory"] = _localized("memory")
                changed = True
            if "heartbeat" not in data:
                data["heartbeat"] = _localized("heartbeat")
                changed = True
            if changed:
                self._save(data)
            return data
        except Exception as exc:
            # Never silently discard a corrupt config (it may hold the only
            # copy of the user's keys): preserve the bytes and say so.
            backup = self.config_file.with_name(
                f"config.json.corrupt-{int(time.time())}"
            )
            try:
                # S9: create the backup private from birth (0600 exclusive);
                # copyfile-then-chmod leaves keys world-readable in between.
                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as dst, open(
                    self.config_file, "rb"
                ) as src:
                    shutil.copyfileobj(src, dst)
                where = f" Original preserved at {backup}."
            except OSError:
                where = " Backup copy FAILED; the corrupt file is untouched."
            print(
                f"Warning: config file {self.config_file} is corrupt "
                f"({exc}); falling back to defaults for this run.{where}",
                file=sys.stderr,
            )
            return {
                "default_provider": "openrouter",
                "providers": copy.deepcopy(DEFAULT_PROVIDERS),
                "keys": {},
                "cloudflare_account_id": "",
                "system_prompt": "You are a helpful, brilliant, concise AI assistant.",
                "temperature": 0.7,
                "timeout": 60,
            }

    def _save(self, data: Optional[Dict[str, Any]] = None) -> None:
        if data is None:
            data = self.data
        # config.json holds provider API keys. Writing in place is unsafe: if the
        # file already exists world-readable, O_CREAT's mode is ignored and the
        # keys are written into the permissive file before any chmod (CWE-378).
        # Write to a private temp file (mkstemp creates it 0600) and atomically
        # replace, so the keys never land in a readable file and there is no
        # permissive window. os.replace is atomic within the same directory.
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(self.config_dir), prefix=".config-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.config_file)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def save(self) -> None:
        self._save(self.data)

    def get_default_provider(self) -> str:
        return self.data.get("default_provider", "openrouter")

    def set_default_provider(self, provider_id: str) -> None:
        provider_id = provider_id.lower()
        if provider_id not in self.data["providers"]:
            raise ValueError(f"Provider '{provider_id}' is not configured.")
        self.data["default_provider"] = provider_id
        self.save()

    def get_provider_info(self, provider_id: str) -> Dict[str, Any]:
        provider_id = provider_id.lower()
        if provider_id not in self.data["providers"]:
            raise KeyError(f"Unknown provider '{provider_id}'. Available: {list(self.data['providers'].keys())}")
        return self.data["providers"][provider_id]

    def _keys_file_candidates(self) -> list:
        """The only env files OmniCLI reads, in precedence order.

        1. OMNICLI_KEYS_FILE — operator-chosen file (explicit integration)
        2. <config_dir>/keys.env — OmniCLI's own standalone store
        3. Trio shared store — TRIO_KEYS_FILE env, else the documented
           ~/.config/trio/keys.env suite convention
        Nothing else. Sibling checkouts are never scavenged: moving a
        repo must not silently change which credentials OmniCLI uses.
        """
        candidates = []
        explicit = os.environ.get("OMNICLI_KEYS_FILE", "").strip()
        if explicit:
            candidates.append(Path(explicit).expanduser())
        candidates.append(self.config_dir / "keys.env")
        trio_env = os.environ.get("TRIO_KEYS_FILE", "").strip()
        candidates.append(
            Path(trio_env).expanduser() if trio_env else TRIO_KEYS_FILE
        )
        seen, out = set(), []
        for p in candidates:
            key = str(p)
            if key not in seen:
                seen.add(key)
                out.append(p)
        return out

    def _read_env_files(self) -> Dict[str, str]:
        env_dict: Dict[str, str] = {}
        candidate_paths = self._keys_file_candidates()
        for path in candidate_paths:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                k = k.strip()
                                v = v.strip().strip("\"'")
                                if k and v and k not in env_dict:
                                    env_dict[k] = v
                except Exception:
                    pass
        return env_dict

    def get_api_key(self, provider_id: str) -> str:
        provider_id = provider_id.lower()
        prov = self.data["providers"].get(provider_id, {})
        env_key = prov.get("env_key")
        # 1. Explicit runtime environment wins (S9): a host process that
        # merged its resolved keys into os.environ (Oracle hunt lane) must
        # not be silently overridden by a stale config.json key. Direct
        # config still beats env *files* below (pinned contract).
        if env_key and os.getenv(env_key):
            return os.getenv(env_key, "").strip()
        for alt in prov.get("alt_env_keys", []):
            if os.getenv(alt):
                return os.getenv(alt, "").strip()

        # 2. Direct config keys
        key = self.data.get("keys", {}).get(provider_id, "")
        if key:
            return key

        # 3. Check the canonical env files (see _keys_file_candidates)
        env_dict = self._read_env_files()
        if env_key and env_key in env_dict:
            return env_dict[env_key]

        for alt in prov.get("alt_env_keys", []):
            if alt in env_dict:
                return env_dict[alt]

        return ""

    def provider_requires_key(self, provider_id: str) -> bool:
        """True when the provider needs a credential before any HTTP.

        Defaults to ``bool(env_key)``. A provider may set
        ``key_required: false`` for a public gateway that accepts an
        OPTIONAL token (e.g. OVHcloud AI Endpoints): the env_key still
        documents how to supply one, but its absence is not an error.
        """
        provider_id = provider_id.lower()
        prov = self.data.get("providers", {}).get(provider_id, {})
        # Configs written before a default field existed do not carry it.
        # Fall back to the shipped default so upgrades pick up new flags
        # (e.g. key_required=false for public gateways).
        if "key_required" not in prov:
            prov = DEFAULT_PROVIDERS.get(provider_id, prov)
        if prov.get("key_required") is False:
            return False
        return bool(prov.get("env_key"))

    def has_credential(self, provider_id: str) -> bool:
        """True when any usable credential resolves for the provider."""
        provider_id = provider_id.lower()
        if self.get_api_key(provider_id):
            return True
        if provider_id == "monkeycode" and self.get_monkeycode_session_cookie():
            return True
        return False

    def configured_provider_ids(self) -> list:
        """Providers (of the configured set) with a resolvable credential."""
        return [
            pid
            for pid in self.data.get("providers", {})
            if self.has_credential(pid)
        ]

    def key_preflight(self) -> Dict[str, Any]:
        """Loud empty-key preflight report (G8) — counts only, no secrets."""
        providers = self.data.get("providers", {})
        configured = self.configured_provider_ids()
        missing = [
            pid
            for pid in providers
            if self.provider_requires_key(pid) and pid not in configured
        ]
        return {
            "config_dir": str(self.config_dir),
            "configured": configured,
            "missing": missing,
            "total_providers": len(providers),
            "keys_files_checked": [
                str(p) for p in self._keys_file_candidates()
            ],
        }

    def missing_key_message(self, provider_id: str) -> str:
        """Actionable no-key error naming the fix, never a bare 401."""
        provider_id = provider_id.lower()
        prov = self.data.get("providers", {}).get(provider_id, {})
        env_key = prov.get("env_key") or "(no env_key declared)"
        report = self.key_preflight()
        return (
            f"no API key for '{provider_id}' (env {env_key}); "
            f"{len(report['configured'])}/{report['total_providers']} "
            f"providers configured in {report['config_dir']}; checked "
            f"process env, config keys, and "
            f"{', '.join(report['keys_files_checked']) or 'no keys files'}; "
            f"add a key (omni config) or point OMNICLI_CONFIG_DIR at the "
            f"config that has keys"
        )

    def set_api_key(self, provider_id: str, key: str) -> None:
        provider_id = provider_id.lower()
        if "keys" not in self.data:
            self.data["keys"] = {}
        self.data["keys"][provider_id] = key.strip()
        self.save()

    def get_cloudflare_account_id(self) -> str:
        # S9 parity with get_api_key: explicit runtime env wins over config.
        if os.getenv("CLOUDFLARE_ACCOUNT_ID"):
            return os.getenv("CLOUDFLARE_ACCOUNT_ID", "").strip()
        acc = self.data.get("cloudflare_account_id", "")
        if acc:
            return acc.strip()

        env_dict = self._read_env_files()
        if "CLOUDFLARE_ACCOUNT_ID" in env_dict:
            return env_dict["CLOUDFLARE_ACCOUNT_ID"]

        return ""

    def set_cloudflare_account_id(self, account_id: str) -> None:
        self.data["cloudflare_account_id"] = account_id.strip()
        self.save()

    def get_monkeycode_signing_secret(self) -> str:
        if os.getenv("MONKEYCODE_SIGNING_SECRET"):
            return os.getenv("MONKEYCODE_SIGNING_SECRET", "").strip()
        env_dict = self._read_env_files()
        return env_dict.get("MONKEYCODE_SIGNING_SECRET", "")

    def get_monkeycode_session_cookie(self) -> str:
        if os.getenv("MONKEYCODE_SESSION_COOKIE"):
            return os.getenv("MONKEYCODE_SESSION_COOKIE", "").strip()
        env_dict = self._read_env_files()
        return env_dict.get("MONKEYCODE_SESSION_COOKIE", "")

    def get_base_url(self, provider_id: str) -> str:
        provider_id = provider_id.lower()
        prov = self.get_provider_info(provider_id)
        if provider_id == "cloudflare":
            account_id = self.get_cloudflare_account_id()
            if not account_id:
                # default placeholder or instructions
                return "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1"
            return f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1"
        return prov.get("base_url", "")

    def get_default_model(self, provider_id: str) -> str:
        prov = self.get_provider_info(provider_id)
        return prov.get("default_model", "")

    def get_fallback_models(self, provider_id: str) -> list:
        """Ordered fallback model roster for a provider (populated by omni scan)."""
        prov = self.get_provider_info(provider_id)
        return list(prov.get("fallback_models") or [])

    def get_memory_config(self) -> dict:
        """Memory settings block (enabled, dir, global, providers, history)."""
        return dict(self.data.get("memory") or {})

    def get_memory_files(self, provider_id: str) -> list:
        """Configured memory file names for a provider: global first, then its own."""
        mem = self.data.get("memory") or {}
        files = list(mem.get("global") or [])
        files += list((mem.get("providers") or {}).get(provider_id.lower()) or [])
        return files

    def get_heartbeat_config(self) -> dict:
        """Heartbeat settings block (canary, status_file, tasks_file)."""
        return dict(self.data.get("heartbeat") or {})

    def get_verification_panel(self, provider_id: str) -> list:
        """Diverse-family verification panel (populated by omni scan).

        Each entry is {"model": str, "family": str}.
        """
        prov = self.get_provider_info(provider_id)
        return list(prov.get("verification_panel") or [])

    def save_scan_results(self, provider_id: str,
                          fallback_models: list,
                          verification_panel: list) -> None:
        """Persist live scan results (roster + panel) for a provider."""
        provider_id = provider_id.lower()
        prov = self.data["providers"].get(provider_id)
        if prov is None:
            return
        prov["fallback_models"] = fallback_models
        prov["verification_panel"] = verification_panel
        self.save()

    def set_default_model(self, provider_id: str, model_id: str) -> None:
        provider_id = provider_id.lower()
        prov = self.get_provider_info(provider_id)
        prov["default_model"] = model_id.strip()
        self.save()

    def add_custom_provider(
        self,
        provider_id: str,
        base_url: str,
        api_key: Optional[str] = None,
        default_model: str = "default",
        name: Optional[str] = None,
    ) -> None:
        provider_id = provider_id.lower().strip()
        self.data["providers"][provider_id] = {
            "name": name or provider_id.capitalize(),
            "base_url": base_url.rstrip("/"),
            "env_key": f"{provider_id.upper()}_API_KEY",
            "default_model": default_model,
            "description": f"Custom OpenAI-compatible provider: {base_url}",
            "requires_auth_for_models": True,
        }
        if api_key:
            self.set_api_key(provider_id, api_key)
        else:
            self.save()

    def remove_provider(self, provider_id: str) -> bool:
        provider_id = provider_id.lower().strip()
        if provider_id in self.data["providers"]:
            del self.data["providers"][provider_id]
            if provider_id in self.data.get("keys", {}):
                del self.data["keys"][provider_id]
            self.save()
            return True
        return False
