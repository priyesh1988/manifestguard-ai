from manifest_guard.analyzers import analyze_document
from manifest_guard.fixes import apply_fix


def _doc():
    return {
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


def test_applies_image_fix():
    doc = _doc()
    finding = next(f for f in analyze_document("demo.yaml", doc) if f.code == "IMAGE_LATEST_TAG")
    action = apply_fix(doc, finding, "pin_image_tag")
    assert action is not None
    assert action.applied is True
    assert doc["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.0.0"


def test_applies_security_fix():
    doc = _doc()
    finding = next(f for f in analyze_document("demo.yaml", doc) if f.code == "RUN_AS_NON_ROOT_MISSING")
    action = apply_fix(doc, finding, "set_run_as_non_root")
    assert action is not None
    assert action.applied is True
    sc = doc["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert sc["runAsNonRoot"] is True
