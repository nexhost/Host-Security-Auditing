from app.engine.history import compare_services


def test_history_detects_ports_and_versions():
    old = {(22, "tcp", "8.0"), (80, "tcp", "1.0")}
    new = {(22, "tcp", "9.0"), (443, "tcp", "1.0")}
    kinds = {change.kind for change in compare_services(old, new)}
    assert kinds == {"NEW PORT", "REMOVED PORT", "VERSION CHANGE"}

