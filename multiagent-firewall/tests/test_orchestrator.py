from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from multiagent_firewall.orchestrator import GuardOrchestrator
from multiagent_firewall.nodes import policy, risk
from multiagent_firewall.config.registry import NODE_REGISTRY
from multiagent_firewall.types import GuardState


def test_orchestrator_initialization(guard_config):
    """Test orchestrator initializes and builds graph"""
    orchestrator = GuardOrchestrator(guard_config)

    # Verify the graph was built
    assert orchestrator._graph is not None


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_run_basic(mock_llm_detector, guard_config):
    """Test basic orchestrator run"""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(text="Hello world")

    assert isinstance(result, dict)
    assert "raw_text" in result
    assert result.get("raw_text") == "Hello world"


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_run_empty_text(mock_llm_detector, guard_config):
    """Test orchestrator with empty text"""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(text="")

    assert result.get("raw_text") == ""
    assert "warnings" in result


@pytest.mark.asyncio
async def test_orchestrator_skips_dlp_policy_when_no_dlp_hits(guard_config):
    """DLP misses should route straight to LLM and bypass DLP risk/policy. If LLM also finds nothing, skip risk/policy entirely."""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})

    with (
        patch(
            "multiagent_firewall.nodes.detection.LiteLLMDetector"
        ) as mock_llm_detector,
        patch.dict(
            "multiagent_firewall.config.registry.NODE_REGISTRY",
            {
                "evaluate_risk": MagicMock(wraps=risk.evaluate_risk),
                "apply_policy": MagicMock(wraps=policy.apply_policy),
            },
        ),
    ):
        mock_evaluate_risk = NODE_REGISTRY["evaluate_risk"]
        mock_apply_policy = NODE_REGISTRY["apply_policy"]

        mock_llm_detector.return_value = mock_detector

        orchestrator = GuardOrchestrator(guard_config)
        result = await orchestrator.run(text="The sky is clear today.")

    # When both DLP and LLM find nothing, skip risk/policy entirely
    assert mock_evaluate_risk.call_count == 0
    assert mock_apply_policy.call_count == 0
    assert result.get("risk_level") == "none"  # Default value
    assert result.get("decision") == "allow"  # Default value


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_short_circuits_on_empty_text(
    mock_llm_detector, guard_config
):
    """Empty text should still run DLP and allow."""
    mock_llm_detector.return_value = MagicMock()

    calls = []

    async def fake_dlp(state):
        calls.append("dlp")
        return state

    with patch.dict(
        "multiagent_firewall.config.registry.NODE_REGISTRY",
        {"run_dlp_detector": fake_dlp},
    ):
        orchestrator = GuardOrchestrator(guard_config)
        result = await orchestrator.run(text="")

    assert "dlp" in calls
    mock_llm_detector.assert_not_called()
    assert result.get("decision") == "allow"
    assert result.get("risk_level") == "none"
    assert not result.get("detected_fields")


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_reuses_dlp_decision_when_llm_adds_nothing(
    mock_llm_detector, guard_config
):
    """Skip final risk/policy when LLM does not add new fields."""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    with patch.dict(
        "multiagent_firewall.config.registry.NODE_REGISTRY",
        {
            "evaluate_risk": MagicMock(wraps=risk.evaluate_risk),
            "apply_policy": MagicMock(wraps=policy.apply_policy),
        },
    ):
        mock_evaluate_risk = NODE_REGISTRY["evaluate_risk"]
        mock_apply_policy = NODE_REGISTRY["apply_policy"]

        orchestrator = GuardOrchestrator(guard_config)
        result = await orchestrator.run(
            text="Reach me at test@example.com", min_block_level="high"
        )

    assert mock_evaluate_risk.call_count == 1  # Only DLP path
    assert mock_apply_policy.call_count == 1
    assert result.get("decision") == "warn"
    assert result.get("risk_level") == "low"


@pytest.mark.asyncio
async def test_orchestrator_skips_llm_when_policy_blocks(guard_config):
    """If policy decides to block, LLM detector should be skipped."""

    async def fake_dlp(state):
        state["dlp_fields"] = [{"type": "EMAIL", "value": "x@example.com"}]
        state["detected_fields"] = state["dlp_fields"]
        return state

    async def fake_risk(state):
        return state | {"risk_level": "high"}

    async def fake_policy(state):
        state["decision"] = "block"
        return state

    calls = []

    async def fake_llm(state, **kwargs):
        calls.append("llm")
        return state

    with patch.dict(
        "multiagent_firewall.config.registry.NODE_REGISTRY",
        {
            "run_dlp_detector": fake_dlp,
            "evaluate_risk": fake_risk,
            "apply_policy": fake_policy,
            "run_llm_detector": fake_llm,
        },
    ):
        orchestrator = GuardOrchestrator(guard_config)
        result = await orchestrator.run(text="x@example.com")

    assert "llm" not in calls
    assert result.get("decision") == "block"


def test_orchestrator_graph_structure(guard_config):
    """Test orchestrator graph structure"""
    orchestrator = GuardOrchestrator(guard_config)
    graph = orchestrator._graph

    assert graph is not None


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_run_with_sensitive_data(mock_llm_detector, guard_config):
    """Test orchestrator with sensitive data detection"""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(
        return_value={
            "detected_fields": [
                {"field": "EMAIL", "value": "test@example.com"},
                {"field": "PASSWORD", "value": "secret123"},
            ]
        }
    )
    mock_llm_detector.return_value = mock_detector

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(
        text="My email is test@example.com and password is secret123",
        min_block_level="high",
    )

    assert "detected_fields" in result
    assert "risk_level" in result
    assert "decision" in result
    assert all("risk" in f for f in result["detected_fields"])
    risk_map = {f["field"]: f["risk"] for f in result["detected_fields"]}
    assert risk_map.get("PASSWORD") == "high"
    assert risk_map.get("EMAIL") == "medium"


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_finalizes_anonymized_text(mock_llm_detector, guard_config):
    """Final anonymization should include LLM-only detections for callers."""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(
        return_value={"detected_fields": [{"field": "PASSWORD", "value": "secret123"}]}
    )
    mock_llm_detector.return_value = mock_detector

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(text="Please use secret123 to proceed")

    masked = result.get("anonymized_text") or ""
    mapping = (
        result.get("metadata", {}).get("llm_anonymized_values", {}).get("mapping", {})
    )
    assert "<<REDACTED:PASSWORD_1>>" in masked
    assert "secret123" not in masked
    assert mapping.get("secret123") == "<<REDACTED:PASSWORD_1>>"


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_skips_final_anonymizer_without_llm(
    mock_llm_detector, guard_config
):
    """Anonymizers should not run when no findings are detected."""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    call_count = {"count": 0}
    from multiagent_firewall import nodes as node_module

    original = node_module.anonymize_text

    def counting_anonymize(state, *, fw_config, findings_key, text_keys):
        call_count["count"] += 1
        return original(
            state, fw_config=fw_config, findings_key=findings_key, text_keys=text_keys
        )

    with patch.dict(
        "multiagent_firewall.config.registry.NODE_REGISTRY",
        {"anonymize_text": counting_anonymize},
    ):
        orchestrator = GuardOrchestrator(guard_config)
        result = await orchestrator.run(text="Hello world")

    # No DLP findings and no LLM findings, so no anonymizers should run
    assert call_count["count"] == 0
    # anonymized_text should not be set when there are no findings
    assert "anonymized_text" not in result or result.get("anonymized_text") == ""


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_run_with_file_path(
    mock_llm_detector, tmp_path, guard_config
):
    """Test orchestrator with file_paths parameter"""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    # Create a test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("File content with SSN 123-45-6789", encoding="utf-8")

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(file_paths=[str(test_file)])

    assert "raw_text" in result
    assert "File content with SSN" in result["raw_text"]
    assert "detected_fields" in result


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_combines_text_and_file(
    mock_llm_detector, tmp_path, guard_config
):
    """Test that both text and file_paths content are combined in raw_text"""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    # Create a test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("File content", encoding="utf-8")

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(text="Direct text", file_paths=[str(test_file)])

    # Both should be present in raw_text
    assert "Direct text" in result.get("raw_text")
    assert "File content" in result.get("raw_text")


@pytest.mark.asyncio
@patch("multiagent_firewall.nodes.detection.LiteLLMDetector")
async def test_orchestrator_preserves_text_on_file_error(
    mock_llm_detector, tmp_path, guard_config
):
    """Test that direct text is preserved when file reading fails"""
    mock_detector = MagicMock()
    mock_detector.acall = AsyncMock(return_value={"detected_fields": []})
    mock_llm_detector.return_value = mock_detector

    # Create path to non-existent file
    missing_file = tmp_path / "missing.txt"

    orchestrator = GuardOrchestrator(guard_config)
    result = await orchestrator.run(text="Direct text", file_paths=[str(missing_file)])

    # Direct text should be preserved even though file reading failed
    assert result.get("raw_text") == "Direct text"
    assert len(result.get("errors", [])) > 0
    assert any("File not found" in error for error in result.get("errors", []))
