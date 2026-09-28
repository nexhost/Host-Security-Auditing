import pytest

from app.integrations.base import MemoryEventSink
from app.integrations.misp import MISPAdapter
from app.integrations.n8n import N8nWebhook


def test_memory_sink_supports_offline_integration_tests():
    sink = MemoryEventSink(); sink.send("scan.completed", {"scan_id": 1})
    assert sink.events == [("scan.completed", {"scan_id": 1})]


def test_integrations_require_https_and_misp_confirmation():
    with pytest.raises(ValueError): N8nWebhook("http://example.test/hook")
    adapter = MISPAdapter("https://misp.example.test", "test-key")
    with pytest.raises(PermissionError): adapter.submit_indicator("1", "domain", "example.test")

