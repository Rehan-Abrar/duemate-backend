"""
Centralized LLM transport with Groq → Groq-secondary → Gemini fallback.

Consumers (NLU, parse_task, agent) call complete_chat() and receive the same
content string regardless of which provider answered. Application JSON parsing
and schema validation stay in the callers — a bad JSON body after HTTP 200 is
NOT retried on another provider.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

from utils.groq_config import GROQ_API_URL, get_gemini_model, get_groq_model

logger = logging.getLogger(__name__)

GEMINI_API_URL_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

_RETRYABLE_STATUS = frozenset({401, 403, 404, 408, 429, 500, 502, 503, 504})
_KEY_RE = re.compile(
    r"(gsk_[A-Za-z0-9]+|AIza[A-Za-z0-9_\-]+|Bearer\s+\S+)",
    re.IGNORECASE,
)


class LLMError(RuntimeError):
    """All configured providers failed, or no credentials were available."""

    def __init__(self, message: str, reason: str = "provider_error"):
        super().__init__(message)
        self.reason = reason


@dataclass
class LLMResult:
    content: str
    provider: str
    credential: str
    model: str
    raw: dict = field(default_factory=dict)
    latency_ms: float = 0.0


def redact(text: object) -> str:
    """Strip credential material from anything that might be logged."""
    return _KEY_RE.sub("[redacted]", str(text or ""))


def _env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def configured_targets() -> list[dict]:
    """
    Return the live fallback chain. Missing keys are omitted.
    Order: GROQ_API_KEY → GROQ_API_KEY_v2 → GEMINI_API_KEY.
    """
    targets = []
    groq_model = get_groq_model()
    if _env("GROQ_API_KEY"):
        targets.append({
            "provider": "groq",
            "credential": "primary",
            "api_key": _env("GROQ_API_KEY"),
            "model": groq_model,
        })
    if _env("GROQ_API_KEY_v2"):
        targets.append({
            "provider": "groq",
            "credential": "secondary",
            "api_key": _env("GROQ_API_KEY_v2"),
            "model": groq_model,
        })
    if _env("GEMINI_API_KEY"):
        targets.append({
            "provider": "gemini",
            "credential": "primary",
            "api_key": _env("GEMINI_API_KEY"),
            "model": get_gemini_model(),
        })
    return targets


def _reason_from_status(status: Optional[int]) -> str:
    if status == 429:
        return "rate_limit"
    if status in (401, 403):
        return "unauthorized"
    if status in (404, 408, 500, 502, 503, 504):
        return "provider_error"
    if status is None:
        return "provider_error"
    return "provider_error"


def _reason_from_exc(exc: Exception) -> str:
    if isinstance(exc, requests.Timeout):
        return "timeout"
    if isinstance(exc, (requests.ConnectionError, requests.exceptions.ChunkedEncodingError)):
        return "connection_error"
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return _reason_from_status(exc.response.status_code)
    return "provider_error"


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, (requests.Timeout, requests.ConnectionError,
                        requests.exceptions.ChunkedEncodingError)):
        return True
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return exc.response.status_code in _RETRYABLE_STATUS
    if isinstance(exc, LLMError):
        return exc.reason in (
            "rate_limit", "unauthorized", "provider_error",
            "timeout", "connection_error", "empty_response",
        )
    # Empty/missing content after HTTP 200
    if isinstance(exc, ValueError) and "empty" in str(exc).lower():
        return True
    return False


def _post_groq(target: dict, system_prompt: str, user_content: str,
               *, json_mode: bool, timeout: float, max_tokens: int,
               temperature: float) -> tuple[str, dict]:
    payload: dict = {
        "model": target["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    headers = {
        "Authorization": f"Bearer {target['api_key']}",
        "Content-Type": "application/json",
    }
    resp = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    content = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    if not str(content).strip():
        raise ValueError("empty model response")
    return str(content), data


def _post_gemini(target: dict, system_prompt: str, user_content: str,
                 *, json_mode: bool, timeout: float, max_tokens: int,
                 temperature: float) -> tuple[str, dict]:
    url = GEMINI_API_URL_TMPL.format(model=target["model"])
    gen_cfg: dict = {
        "temperature": temperature,
        "maxOutputTokens": max_tokens,
    }
    if json_mode:
        gen_cfg["responseMimeType"] = "application/json"
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_content}]}],
        "generationConfig": gen_cfg,
    }
    # Header instead of ?key= so URLs never contain the credential
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": target["api_key"],
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    parts = (
        (data.get("candidates") or [{}])[0]
        .get("content", {})
        .get("parts") or []
    )
    content = "".join(p.get("text") or "" for p in parts if isinstance(p, dict))
    if not content.strip():
        raise ValueError("empty model response")
    usage = data.get("usageMetadata") or {}
    data = {
        **data,
        "usage": {
            "prompt_tokens": usage.get("promptTokenCount", 0),
            "completion_tokens": usage.get("candidatesTokenCount", 0),
            "total_tokens": usage.get("totalTokenCount", 0),
        },
    }
    return content, data


def _log_attempt(*, db, target, caller, prompt_version, system_prompt, user_content,
                 raw, latency_ms, success, error, parse_method, reason=None):
    try:
        from utils.llm_logger import log_llm_call
        log_llm_call(
            db=db,
            model=target["model"],
            prompt_version=prompt_version,
            caller=caller,
            system_prompt=system_prompt,
            user_message=user_content,
            response_data=raw if success else None,
            latency_ms=latency_ms,
            parse_method=parse_method,
            success=success,
            error=redact(error) if error else None,
            provider=target["provider"],
            credential_slot=target["credential"],
            fallback_reason=reason,
        )
    except Exception as log_exc:
        logger.debug("llm_client: llm_logger skipped: %s", log_exc)


def complete_chat(
    system_prompt: str,
    user_content: str,
    *,
    json_mode: bool = True,
    timeout: float = 15.0,
    max_tokens: int = 400,
    temperature: float = 0.1,
    db=None,
    caller: str = "llm_client",
    prompt_version: str = "unknown",
    parse_method: str = "llm",
) -> LLMResult:
    """
    Try configured providers in order. Returns the first successful content string.
    Raises LLMError when nothing is configured or every retryable attempt fails.
    """
    targets = configured_targets()
    if not targets:
        raise LLMError("no LLM credentials configured", reason="no_credentials")

    last_error: Optional[Exception] = None
    last_reason = "provider_error"

    for index, target in enumerate(targets):
        t0 = time.perf_counter()
        try:
            if target["provider"] == "groq":
                content, raw = _post_groq(
                    target, system_prompt, user_content,
                    json_mode=json_mode, timeout=timeout,
                    max_tokens=max_tokens, temperature=temperature,
                )
            else:
                content, raw = _post_gemini(
                    target, system_prompt, user_content,
                    json_mode=json_mode, timeout=timeout,
                    max_tokens=max_tokens, temperature=temperature,
                )
            latency_ms = (time.perf_counter() - t0) * 1000
            if index == 0:
                logger.info(
                    "llm provider=%s credential=%s model=%s",
                    target["provider"], target["credential"], target["model"],
                )
            else:
                logger.info(
                    "llm fallback provider=%s credential=%s model=%s",
                    target["provider"], target["credential"], target["model"],
                )
            _log_attempt(
                db=db, target=target, caller=caller, prompt_version=prompt_version,
                system_prompt=system_prompt, user_content=user_content,
                raw=raw, latency_ms=latency_ms, success=True, error=None,
                parse_method=parse_method, reason=None,
            )
            return LLMResult(
                content=content,
                provider=target["provider"],
                credential=target["credential"],
                model=target["model"],
                raw=raw,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            reason = _reason_from_exc(exc)
            last_error = exc
            last_reason = reason
            safe = redact(exc)
            logger.warning(
                "llm failed provider=%s credential=%s model=%s reason=%s error=%s",
                target["provider"], target["credential"], target["model"], reason, safe,
            )
            _log_attempt(
                db=db, target=target, caller=caller, prompt_version=prompt_version,
                system_prompt=system_prompt, user_content=user_content,
                raw=None, latency_ms=latency_ms, success=False, error=safe,
                parse_method=parse_method, reason=reason,
            )
            if not _is_retryable(exc):
                raise LLMError(safe, reason=reason) from exc
            remaining = targets[index + 1:]
            if remaining:
                nxt = remaining[0]
                logger.info(
                    "llm fallback provider=%s credential=%s reason=%s",
                    nxt["provider"], nxt["credential"], reason,
                )
            continue

    raise LLMError(redact(last_error) if last_error else "all LLM providers failed",
                   reason=last_reason)
