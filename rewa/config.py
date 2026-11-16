"""Central configuration for the Endpoint Ransomware Early-Warning Agent (REWA).

All values can be overridden with environment variables (see .env.example).
No secrets are hard-coded; the default LLM runs locally through Ollama.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
GENERATED_DIR = DATA_DIR / "generated"
DEMO_DIR = DATA_DIR / "demo"
KB_DIR = ROOT_DIR / "knowledge_base"
EVAL_DIR = ROOT_DIR / "eval"
LOG_DIR = Path(os.getenv("REWA_LOG_DIR", ROOT_DIR / "logs"))
MODEL_DIR = ROOT_DIR / "models"

# ---------------- LLM ----------------
# Provider: "ollama" (native /api/chat with tool calling), "openai" (any
# OpenAI-compatible server such as LM Studio) or "offline" (deterministic
# planner, no LLM - used as a safe fallback and for CI).
LLM_PROVIDER = os.getenv("REWA_LLM_PROVIDER", "ollama")
LLM_BASE_URL = os.getenv("REWA_LLM_BASE_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("REWA_LLM_MODEL", "qwen2.5:7b-instruct")
LLM_API_KEY = os.getenv("REWA_LLM_API_KEY", "")  # only for OpenAI-compatible servers
LLM_TIMEOUT_S = float(os.getenv("REWA_LLM_TIMEOUT_S", "90"))
LLM_TEMPERATURE = float(os.getenv("REWA_LLM_TEMPERATURE", "0.1"))
AGENT_MAX_STEPS = int(os.getenv("REWA_AGENT_MAX_STEPS", "8"))
# Whole-investigation time limit for the LLM path. When it runs out (slow laptop CPU, model still
# loading) the agent finishes with the deterministic planner instead of leaving the UI hanging.
AGENT_TIME_BUDGET_S = float(os.getenv("REWA_AGENT_TIME_BUDGET_S", "240"))
LLM_NUM_CTX = int(os.getenv("REWA_LLM_NUM_CTX", "8192"))
LLM_KEEP_ALIVE = os.getenv("REWA_LLM_KEEP_ALIVE", "30m")  # keep the model in memory between investigations

# ---------------- RAG ----------------
# "tfidf" works everywhere with zero downloads. "sbert" uses
# sentence-transformers (e.g. BAAI/bge-small-en-v1.5) if installed.
EMBEDDING_BACKEND = os.getenv("REWA_EMBEDDING_BACKEND", "tfidf")
EMBEDDING_MODEL = os.getenv("REWA_EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
RAG_TOP_K = int(os.getenv("REWA_RAG_TOP_K", "4"))

# ---------------- Scoring ----------------
ALERT_THRESHOLD = float(os.getenv("REWA_ALERT_THRESHOLD", "45"))
LEVELS = [  # (lower bound inclusive, label)
    (70.0, "CRITICAL"),
    (45.0, "HIGH"),
    (25.0, "MEDIUM"),
    (0.0, "LOW"),
]

# ---------------- Safety ----------------
# The MVP never executes containment. Approved actions are only written to
# the audit log as "simulated" tickets for a human responder.
EXECUTE_CONTAINMENT = False
MAX_UPLOAD_ROWS = int(os.getenv("REWA_MAX_UPLOAD_ROWS", "200000"))


def risk_level(score: float) -> str:
    for lower, label in LEVELS:
        if score >= lower:
            return label
    return "LOW"
