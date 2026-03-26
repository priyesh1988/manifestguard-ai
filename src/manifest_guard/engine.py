from __future__ import annotations

import uuid
from dataclasses import asdict
from pathlib import Path

from .analyzers import analyze_document
from .config import Defaults
from .fixes import apply_fix, choose_patch_name
from .memory import MemoryStore
from .utils import deep_copy_doc, dump_yaml_documents, iter_yaml_files, load_yaml_documents


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def scan_target(target: Path) -> list[dict]:
    results: list[dict] = []
    for file_path in iter_yaml_files(target):
        docs = load_yaml_documents(file_path)
        for idx, doc in enumerate(docs):
            findings = analyze_document(str(file_path), doc)
            results.append({
                "file_path": str(file_path),
                "document_index": idx,
                "findings": findings,
            })
    return results


def highest_severity(findings: list) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0)).severity


def fix_target(target: Path, memory: MemoryStore, write: bool = False, defaults: Defaults | None = None) -> dict:
    defaults = defaults or Defaults()
    run_id = str(uuid.uuid4())
    summary = {
        "run_id": run_id,
        "files": [],
        "totals": {"findings": 0, "fixed": 0, "unchanged": 0},
    }

    for file_path in iter_yaml_files(target):
        docs = load_yaml_documents(file_path)
        original_docs = [deep_copy_doc(d) for d in docs]
        file_result = {"file_path": str(file_path), "documents": []}

        for idx, doc in enumerate(docs):
            findings = analyze_document(str(file_path), doc)
            actions = []
            for finding in findings:
                learned_patch = memory.best_patch_for_signature(finding.signature or "") if defaults.enable_learning else None
                patch_name = choose_patch_name(finding, learned_patch)
                action = apply_fix(doc, finding, patch_name, defaults=defaults)
                success = bool(action and action.applied)
                memory.record(run_id, finding, action, success=success)
                if success:
                    summary["totals"]["fixed"] += 1
                else:
                    summary["totals"]["unchanged"] += 1
                actions.append({
                    "finding": asdict(finding),
                    "action": asdict(action) if action else None,
                    "learned_patch": learned_patch,
                    "memory_stats": memory.stats_for_signature(finding.signature or ""),
                })
            summary["totals"]["findings"] += len(findings)
            file_result["documents"].append({
                "document_index": idx,
                "actions": actions,
            })

        if write and docs != original_docs:
            dump_yaml_documents(file_path, docs)

        summary["files"].append(file_result)

    return summary
