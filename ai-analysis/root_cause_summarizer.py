from dotenv import load_dotenv
load_dotenv()
import os
import json
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)
def summarize_incident(incident: dict) -> dict:
    """
    Advisory-only: summarizes an ALREADY-SCORED incident in plain English.
    Refuses to run on an incident missing a risk_score, per project's
    non-negotiable rule that the LLM never becomes the detection source.
    """
    if "risk_score" not in incident:
        raise ValueError(
            "summarize_incident() requires an incident with a risk_score. "
            "The LLM is advisory-only and must never be called before "
            "the Correlation Engine has scored the incident."
        )

    prompt = f"""You are a container security analyst. Given this incident,
respond ONLY in JSON with keys: root_cause, severity (low/medium/high/critical),
recommended_action, plain_summary.

Incident: {incident}
"""

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )

    return json.loads(response.choices[0].message.content)