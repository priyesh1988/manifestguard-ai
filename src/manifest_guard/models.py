from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Finding:
    code: str
    title: str
    severity: str
    path: str
    resource_kind: str
    resource_name: str
    namespace: str | None
    container_name: str | None
    message: str
    fixable: bool
    recommended_patch: str | None = None
    signature: str | None = None


@dataclass(slots=True)
class FixAction:
    issue_code: str
    patch_name: str
    description: str
    applied: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ResourceDocument:
    file_path: str
    index: int
    doc: dict[str, Any]
