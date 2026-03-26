from pathlib import Path

from manifest_guard.analyzers import analyze_document
from manifest_guard.fixes import apply_fix
from manifest_guard.memory import MemoryStore


def test_memory_learns_preferred_patch(tmp_path: Path):
    db = tmp_path / "history.sqlite3"
    store = MemoryStore(db)
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "demo"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "web", "image": "nginx:latest"}
                    ]
                }
            }
        },
    }
    finding = next(f for f in analyze_document("demo.yaml", doc) if f.code == "IMAGE_LATEST_TAG")
    action = apply_fix(doc, finding, "pin_image_tag")
    store.record("run-1", finding, action, success=True)
    assert store.best_patch_for_signature(finding.signature) == "pin_image_tag"
    stats = store.stats_for_signature(finding.signature)
    assert stats["total"] == 1
    assert stats["successes"] == 1
    store.close()
