from pathlib import Path

from manifest_guard.policy_export import export_builtin_kyverno


def test_export_builtin_kyverno(tmp_path: Path) -> None:
    out = tmp_path / 'policies.yaml'
    export_builtin_kyverno(out)
    text = out.read_text(encoding='utf-8')
    assert 'ClusterPolicy' in text
    assert 'manifestguard-require-non-root' in text
