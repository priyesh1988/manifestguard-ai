from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .models import Finding


def findings_to_json(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]


def write_report(output: Path, payload: dict) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
