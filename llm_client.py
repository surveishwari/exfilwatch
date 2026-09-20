"""
ExfilWatch — LLM Client
Thin wrapper around the Groq API (OpenAI-compatible chat completions).
This is what makes the live-attack demo honest: the reply that gets
tampered with and caught is a genuine model output, not a canned string.

Requires the GROQ_API_KEY environment variable. Get a free key at
https://console.groq.com/keys — Groq's free tier is generous and fast,
and this demo uses a handful of very short calls (a few hundred tokens
each), so it stays well within it.
"""

import os
import httpx

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = os.environ.get("EXFILWATCH_LLM_MODEL", "openai/gpt-oss-20b")


class LLMNotConfigured(Exception):
    """Raised when no API key is set, so the caller can fall back gracefully."""


async def get_agent_reply(user_question: str) -> str:
    """
    Send `user_question` to the real Groq-hosted model as if it were a
    support agent, and return the plain-text reply. Raises
    LLMNotConfigured if GROQ_API_KEY isn't set, so the frontend can show
    a clear message instead of a raw stack trace.
    """
    if not GROQ_API_KEY:
        raise LLMNotConfigured("GROQ_API_KEY is not set on the server.")

    payload = {
        "model": MODEL,
        "max_tokens": 200,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a helpful customer support assistant for a "
                    "software company. Answer the user's question in 2-3 "
                    "natural sentences. Do not mention that you are an AI "
                    "model or that this is a test."
                ),
            },
            {"role": "user", "content": user_question},
        ],
    }
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(GROQ_URL, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    choices = data.get("choices", [])
    reply = choices[0]["message"]["content"].strip() if choices else ""
    if not reply:
        raise LLMNotConfigured("Model returned no text content.")
    return reply


def _require_key():
    if not GROQ_API_KEY:
        raise LLMNotConfigured("GROQ_API_KEY is not set on the server.")


async def chat_completion(payload: dict) -> dict:
    """
    Forward an OpenAI-format chat request to the upstream model and return
    the raw response dict. Only whitelisted fields are forwarded, the model
    is pinned server-side, and max_tokens is capped, so a caller can't use
    the gateway to burn the upstream quota or reach other models.
    """
    _require_key()
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("`messages` must be a non-empty list.")
    body = {
        "model": MODEL,
        "messages": messages,
        "max_tokens": min(int(payload.get("max_tokens") or 512), 1024),
    }
    if isinstance(payload.get("temperature"), (int, float)):
        body["temperature"] = payload["temperature"]
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(GROQ_URL, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()
