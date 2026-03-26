from manifest_guard.analyzers import analyze_document


def test_detects_common_issues():
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
    findings = analyze_document("demo.yaml", doc)
    codes = {f.code for f in findings}
    assert "IMAGE_LATEST_TAG" in codes
    assert "MISSING_RESOURCE_REQUESTS" in codes
    assert "MISSING_RESOURCE_LIMITS" in codes
    assert "RUN_AS_NON_ROOT_MISSING" in codes
