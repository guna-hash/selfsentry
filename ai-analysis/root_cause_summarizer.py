"""
root_cause_summarizer.py
----------------------------
Module 8 of ContainerGuard AI: AI Threat Analysis.

STATUS: NOT YET IMPLEMENTED — Phase 7 stub.

CRITICAL DESIGN CONSTRAINT: the LLM is advisory-only. The correlation
engine's deterministic risk score (Phase 5) is the actual detection
signal — this module only explains/summarizes ALREADY-SCORED incidents
in plain English. It must never be able to suppress or fabricate a
detection.

Planned interface (using OpenAI-compatible client — see requirements.txt):
    def summarize_incident(incident: dict) -> dict:
        \"\"\"
        Calls an OpenAI-compatible chat completion (hosted API, or local
        Ollama at http://localhost:11434/v1) with a structured prompt and
        returns {"root_cause": ..., "severity": ..., "recommended_action": ...,
        "plain_summary": ...} parsed from JSON.
        \"\"\"
        raise NotImplementedError("Phase 7 not yet built")

Env vars required (see .env.example): OPENAI_API_KEY
"""
