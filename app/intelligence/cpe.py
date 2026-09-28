from __future__ import annotations

import re

CPE_RE = re.compile(r"^cpe:2\.3:[aho]:[^:]+:[^:]+:.*$|^cpe:/[aho]:[^:]+:[^:]+(?::.*)?$")


def normalize_cpe(value: str) -> str | None:
    candidate = value.strip().lower()
    return candidate if CPE_RE.match(candidate) else None

