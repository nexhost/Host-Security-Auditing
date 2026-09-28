from pathlib import Path
from unittest.mock import patch

from app.scanners.nmap import NmapScanner


def test_adapter_uses_argument_list_and_no_shell(tmp_path):
    class FakeProcess:
        returncode = 0
        def __init__(self, args, **kwargs):
            Path(args[args.index("-oX") + 1]).write_text("<nmaprun/>")
        def poll(self): return 0
        def communicate(self, timeout=None): return "", ""

    scanner = NmapScanner(tmp_path)
    with patch("app.scanners.nmap.shutil.which", return_value="/usr/bin/nmap"), patch("app.scanners.nmap.subprocess.Popen", side_effect=FakeProcess) as run:
        execution = scanner.scan("192.168.1.10", "quick")
    args, kwargs = run.call_args
    assert isinstance(args[0], list)
    assert kwargs["shell"] is False
    assert args[0][-2:] == ["--", "192.168.1.10"]
    assert execution.exit_code == 0
