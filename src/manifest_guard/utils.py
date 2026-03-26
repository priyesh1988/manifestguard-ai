from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Iterable

import yaml

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}


def load_yaml_documents(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    docs = [doc for doc in yaml.safe_load_all(text) if doc]
    return [doc for doc in docs if isinstance(doc, dict)]


def dump_yaml_documents(path: Path, docs: Iterable[dict[str, Any]]) -> None:
    rendered = yaml.safe_dump_all(
        list(docs),
        default_flow_style=False,
        sort_keys=False,
    )
    path.write_text(rendered, encoding="utf-8")


def iter_yaml_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(
        p for p in target.rglob("*")
        if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}
    )


def deep_copy_doc(doc: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(doc)


def resource_identity(doc: dict[str, Any]) -> tuple[str, str, str | None]:
    metadata = doc.get("metadata", {}) or {}
    return (
        str(doc.get("kind", "Unknown")),
        str(metadata.get("name", "unnamed")),
        metadata.get("namespace"),
    )


def pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return (((doc.get("spec") or {}).get("template") or {}).get("spec"))
    if kind == "CronJob":
        return (((((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec"))
    return None


def containers_from_spec(spec: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not spec:
        return []
    return list(spec.get("containers") or [])


def ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        value = {}
        parent[key] = value
    return value
