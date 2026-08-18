from zscope.alerts.verifier import AlertVerifier
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.rules.analyzer import RuleDrivenAnalyzer


class CloseTrackingClient:
    def __init__(self) -> None:
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


def test_analyzer_closes_only_owned_llm_clients() -> None:
    owned = CloseTrackingClient()
    analyzer = Analyzer.__new__(Analyzer)
    analyzer._owns_llm_clients = True
    analyzer.llm_clients = {"default": owned, "alias": owned}

    analyzer.close()

    assert owned.close_count == 1

    shared = CloseTrackingClient()
    analyzer = Analyzer.__new__(Analyzer)
    analyzer._owns_llm_clients = False
    analyzer.llm_clients = {"default": shared}

    analyzer.close()

    assert shared.close_count == 0


def test_parallel_analyzer_close_closes_shared_clients_once() -> None:
    client = CloseTrackingClient()
    analyzer = ParallelAnalyzer.__new__(ParallelAnalyzer)
    analyzer._shared_llm_clients = {"default": client, "alias": client}

    analyzer.close()

    assert client.close_count == 1


def test_offline_alert_verifier_does_not_own_an_llm_client() -> None:
    alert_client = CloseTrackingClient()
    verifier = AlertVerifier.__new__(AlertVerifier)
    verifier.llm_client = alert_client

    verifier.close()

    assert alert_client.close_count == 0


def test_rule_analyzer_closes_llm_clients_once() -> None:

    rule_client = CloseTrackingClient()
    rule_analyzer = RuleDrivenAnalyzer.__new__(RuleDrivenAnalyzer)
    rule_analyzer.llm_clients = {"default": rule_client, "alias": rule_client}

    rule_analyzer.close()

    assert rule_client.close_count == 1
