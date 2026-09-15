"""Tests de l'empreinte comportementale LLM."""
import json

import pytest

import behavioral


@pytest.mark.parametrize(
    "body",
    [
        '{"thought": "I need to enumerate endpoints", "action": "http_get"}',
        '{"steps": [{"observation": "404 returned", "action_input": {"p": 1}}]}',
        '{"agent_scratchpad": "trying /admin next"}',
    ],
)
def test_agent_scaffold_keys_are_detected(body):
    reasons = behavioral.detect_llm_artifacts(body_text=body)
    assert any(r.startswith("agent_scaffold_keys") for r in reasons)


def test_assistant_phrasing_is_detected():
    reasons = behavioral.detect_llm_artifacts(
        body_text="I apologize, but I cannot assist with that request."
    )
    assert any(r.startswith("assistant_phrasing") for r in reasons)


def test_markdown_in_payload_is_detected():
    reasons = behavioral.detect_llm_artifacts(body_text="```json\n{\"a\": 1}\n```")
    assert "markdown_formatting" in reasons


def test_natural_language_in_query_is_detected():
    reasons = behavioral.detect_llm_artifacts(
        query_string="q=list all internal admin endpoints please"
    )
    assert "natural_language_in_query" in reasons


@pytest.mark.parametrize(
    "query,body",
    [
        ("", ""),
        ("id=42&include=meta", ""),
        ("", '{"resource_id": "42", "include_metadata": true}'),
        ("", "username=admin&password=hunter2"),
        ("page=2&per_page=50", ""),
    ],
)
def test_normal_traffic_produces_no_artifacts(query, body):
    """Le signal est discriminant : il ne doit pas se déclencher sur du trafic banal."""
    assert behavioral.detect_llm_artifacts(query_string=query, body_text=body) == []


def test_malformed_json_body_does_not_crash():
    assert isinstance(behavioral.detect_llm_artifacts(body_text="{not json at all"), list)


def test_deeply_nested_body_is_bounded():
    payload = {"a": {}}
    node = payload["a"]
    for _ in range(50):
        node["a"] = {}
        node = node["a"]
    node["thought"] = "hidden very deep"
    # Ne doit ni exploser ni partir en récursion infinie.
    assert isinstance(behavioral.detect_llm_artifacts(body_text=json.dumps(payload)), list)


def test_inference_latency_band_is_recognised():
    # Cadence typique d'un agent : quelques secondes, modérément variable.
    intervals = [2.1, 3.4, 2.8, 4.2, 3.1, 2.5]
    assert behavioral.has_inference_latency_signature(intervals)


@pytest.mark.parametrize(
    "intervals,reason",
    [
        ([0.01, 0.02, 0.015, 0.012, 0.02], "trop rapide : script"),
        ([120.0, 300.0, 95.0, 400.0, 220.0], "trop lent : lecture humaine"),
        ([3.0, 3.0, 3.0, 3.0, 3.0], "trop régulier : cron"),
        ([1.0, 40.0, 0.5, 90.0, 2.0], "trop erratique"),
        ([1.0, 2.0], "échantillon insuffisant"),
    ],
)
def test_non_agent_cadences_are_rejected(intervals, reason):
    assert not behavioral.has_inference_latency_signature(intervals), reason
