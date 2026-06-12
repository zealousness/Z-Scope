from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.specs import SpecRegistry


class RefreshDecisionLLM:
    def __init__(self, content: str):
        self.content = content
        self.messages = []
        self.kwargs = {}

    def chat_completion(self, messages, **kwargs):
        self.messages = messages
        self.kwargs = kwargs
        return {"choices": [{"message": {"content": self.content}}]}


def _analyzer_with_refresh_llm(content: str) -> tuple[Analyzer, RefreshDecisionLLM]:
    analyzer = object.__new__(Analyzer)
    llm = RefreshDecisionLLM(content)
    analyzer.llm_clients = {"default": llm}
    analyzer.spec_registry = SpecRegistry()
    return analyzer, llm


def test_snapshot_refresh_uses_refresh_decision_contract() -> None:
    analyzer, llm = _analyzer_with_refresh_llm(
        """
        ```json
        {
          "type": "snapshot_refresh_decision",
          "func_name": "cache_get",
          "refresh_needed": false,
          "reason": "仅注释变化",
          "what_changed": ["注释文本变化"],
          "risk_if_not_refreshed": "low"
        }
        ```
        """
    )

    decision = analyzer._ask_refresh_decision(
        "cache_get",
        {"summary": "旧摘要", "semantic_fingerprint": "abc"},
        "int cache_get(void) { return 0; }",
    )

    assert decision["refresh_needed"] is False
    assert llm.kwargs["trace_agent"] == "snapshot_refresh_decision"
    assert "snapshot_refresh_decision" in llm.messages[0]["content"]
    assert "function_snapshot" not in llm.messages[0]["content"]


def test_snapshot_refresh_rejects_function_snapshot_payload() -> None:
    analyzer, _llm = _analyzer_with_refresh_llm(
        """
        ```json
        {
          "type": "function_snapshot",
          "func_name": "cache_get",
          "summary": "错误类型",
          "key_semantics": [],
          "inputs": []
        }
        ```
        """
    )

    decision = analyzer._ask_refresh_decision(
        "cache_get",
        {"summary": "旧摘要", "semantic_fingerprint": "abc"},
        "int cache_get(void) { return 1; }",
    )

    assert decision["refresh_needed"] is True
    assert decision["reason"] == "Failed to parse decision"
