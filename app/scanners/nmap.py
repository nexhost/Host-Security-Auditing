from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.core.exceptions import ScannerError, ScannerTimeout, ScannerUnavailable, ValidationError
from app.core.logging import redact
from app.scanners.base import ScanExecution, ScannerAdapter

PROFILES: dict[str, tuple[str, ...]] = {
    "quick": ("-T3", "--top-ports", "100", "-sV", "--version-light"),
    "standard": ("-T3", "-sV", "-O", "--version-light"),
    "deep": ("-T3", "-p-", "-sV", "-O", "--script", "safe,default"),
    "compliance": ("-T2", "-sV", "--script", "safe"),
}


class NmapScanner(ScannerAdapter):
    def __init__(self, output_dir: Path, executable: str = "nmap", timeout: int = 300, safe_mode: bool = True):
        self.output_dir = output_dir
        self.executable = executable
        self.timeout = timeout
        self.safe_mode = safe_mode
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._cancelled = threading.Event()

    def cancel(self) -> bool:
        self._cancelled.set()
        with self._lock:
            process = self._process
        if process and process.poll() is None:
            process.terminate()
            return True
        return False

    def scan(self, target: str, profile: str) -> ScanExecution:
        if profile not in PROFILES:
            raise ValidationError(f"Unknown scan profile: {profile}")
        resolved = shutil.which(self.executable)
        if not resolved:
            raise ScannerUnavailable("Nmap is not installed or is not on PATH")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        xml_path = self.output_dir / f"scan-{uuid4().hex}.xml"
        args = [resolved, *PROFILES[profile], "-oX", str(xml_path), "--", target]
        # Safe mode intentionally excludes aggressive timing, spoofing, evasion, brute force,
        # vulnerability and exploit script categories.
        started = datetime.now(timezone.utc)
        logging.getLogger("scanner").info("Starting authorized scan profile=%s target=%s", profile, target)
        self._cancelled.clear()
        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
            with self._lock:
                self._process = process
            deadline = time.monotonic() + self.timeout
            while process.poll() is None:
                if self._cancelled.wait(0.1):
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=5)
                    raise ScannerError("Scan cancelled by user")
                if time.monotonic() >= deadline:
                    process.terminate()
                    process.communicate(timeout=5)
                    raise ScannerTimeout(f"Nmap exceeded the {self.timeout}s timeout")
            stdout, stderr = process.communicate()
        except OSError as exc:
            raise ScannerError(f"Could not start Nmap: {exc}") from exc
        finally:
            with self._lock:
                self._process = None
        finished = datetime.now(timezone.utc)
        if process.returncode != 0:
            raise ScannerError(f"Nmap failed (exit {process.returncode}): {redact(stderr)[:500]}")
        if not xml_path.exists():
            raise ScannerError("Nmap completed without producing XML output")
        return ScanExecution(
            target=target,
            profile=profile,
            command=tuple(args),
            xml_path=xml_path,
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            exit_code=process.returncode,
            stdout=redact(stdout),
            stderr=redact(stderr),
        )
