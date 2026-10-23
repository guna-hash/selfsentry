"""Optional AI must not make imports or test discovery require a provider."""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("filename", ["test_manual_check.py", "test_timeline_check.py"])
def test_manual_diagnostic_import_has_no_provider_side_effects(filename):
    with patch("openai.OpenAI") as provider:
        spec = importlib.util.spec_from_file_location("diagnostic", ROOT / filename)
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    provider.assert_not_called()


@pytest.mark.parametrize("module_name,function_name,result", [
    ("attack_timeline_builder", "build_timeline", '{"timeline": []}'),
    ("root_cause_summarizer", "summarize_incident", '{"plain_summary": "observed"}'),
])
def test_advisory_requests_have_bounded_lifetime_and_close_clients(
    module_name, function_name, result, monkeypatch
):
    monkeypatch.syspath_prepend(str(ROOT / "ai-analysis"))
    monkeypatch.setenv("GROQ_API_KEY", "test-only-key")
    module = __import__(module_name)
    client = MagicMock()
    client.chat.completions.create.return_value.choices[0].message.content = result
    with patch("openai.OpenAI") as provider:
        provider.return_value.__enter__.return_value = client
        args = ({"risk_score": 10}, []) if function_name == "build_timeline" else (
            {"risk_score": 10},
        )
        getattr(module, function_name)(*args)
    assert provider.call_args.kwargs["timeout"] == 15
    assert provider.call_args.kwargs["max_retries"] == 0
    provider.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("module_name,function_name", [
    ("attack_timeline_builder", "build_timeline"),
    ("root_cause_summarizer", "summarize_incident"),
])
@pytest.mark.parametrize("content", [None, ""])
def test_advisory_refuses_an_empty_provider_response(
    module_name, function_name, content, monkeypatch
):
    monkeypatch.syspath_prepend(str(ROOT / "ai-analysis"))
    monkeypatch.setenv("GROQ_API_KEY", "test-only-key")
    module = __import__(module_name)
    client = MagicMock()
    client.chat.completions.create.return_value.choices[0].message.content = content
    with patch("openai.OpenAI") as provider:
        provider.return_value.__enter__.return_value = client
        args = ({"risk_score": 10}, []) if function_name == "build_timeline" else (
            {"risk_score": 10},
        )
        with pytest.raises(ValueError, match="no JSON content"):
            getattr(module, function_name)(*args)
    provider.return_value.__exit__.assert_called_once()
