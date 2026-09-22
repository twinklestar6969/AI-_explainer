"""Thin Groq chat client with JSON-mode responses."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from groq import Groq

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")


DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"


class GroqJSONClient:
    """Calls Groq Chat Completions and returns a parsed JSON object."""

    def __init__(self, api_key: str, model: str):
        self.model = model
        self._client = Groq(api_key=api_key)

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        max_tokens: int = 900,
    ) -> dict[str, Any]:
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content or ""
        parsed = json.loads(content)

        if not isinstance(parsed, dict):
            raise ValueError("LLM response JSON must be an object")

        return parsed


def groq_client_from_env() -> GroqJSONClient | None:
    """Build a Groq client when LLM is enabled and GROQ_API_KEY is set."""

    if not _env_flag("LLM_ENABLED", default=True):
        return None

    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
    if not api_key:
        return None

    provider = (os.getenv("LLM_PROVIDER") or "groq").strip().lower()
    if provider and provider != "groq":
        return None

    model = (os.getenv("LLM_MODEL") or DEFAULT_GROQ_MODEL).strip()
    return GroqJSONClient(api_key=api_key, model=model)


def _env_flag(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
