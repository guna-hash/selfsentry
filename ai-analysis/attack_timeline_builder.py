from dotenv import load_dotenv
load_dotenv()

import os
import json
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)


def build_timeline(incident: dict, related_events: list[dict]) -> list[dict]:
    """
    Advisory-only: reconstructs a chronological, plain-English attacker
    timeline from an ALREADY-SCORED incident's related events.
    Refuses to run on an incident missing a risk_score, per project's
    non-negotiable rule that the LLM never becomes the detection source.
    """
    if "risk_score" not in incident:
        raise ValueError(
            "build_timeline() requires an incident with a risk_score. "
            "The LLM is advisory-only and must never be called before "
            "the Correlation Engine has scored the incident."
        )

    prompt = f"""You are a container security analyst. Given this incident
and its related events, reconstruct a chronological, plain-English attack
timeline. Respond ONLY in JSON with a single key "timeline", whose value is
a list of objects, each with keys: step (int), description (string).

Incident: {incident}
Related events: {related_events}
"""

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )

    parsed = json.loads(response.choices[0].message.content)
    return parsed["timeline"]