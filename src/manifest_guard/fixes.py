from __future__ import annotations

from typing import Any

from .config import Defaults
from .models import Finding, FixAction
from .utils import containers_from_spec, ensure_dict, pod_spec




def _find_container(spec: dict[str, Any], name: str | None) -> dict[str, Any] | None:
    for c in containers_from_spec(spec):
        if c.get("name") == name:
            return c
    return None


def choose_patch_name(finding: Finding, learned_patch: str | None) -> str | None:
    if learned_patch:
        return learned_patch
    return finding.recommended_patch


def apply_fix(doc: dict[str, Any], finding: Finding, patch_name: str | None, defaults: Defaults | None = None) -> FixAction | None:
    defaults = defaults or Defaults()
    if not patch_name:
        return None
    spec = pod_spec(doc)
    if not spec:
        return None

    if patch_name == "disable_automount_sa_token":
        spec["automountServiceAccountToken"] = False
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Disabled automountServiceAccountToken", applied=True)

    if patch_name == "disable_host_network":
        spec["hostNetwork"] = False
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Disabled hostNetwork", applied=True)

    container = _find_container(spec, finding.container_name)
    if container is None:
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Container not found", applied=False)

    if patch_name == "pin_image_tag":
        image = str(container.get("image", ""))
        if ":" in image:
            base, _ = image.rsplit(":", 1)
        else:
            base = image
        container["image"] = f"{base}:{defaults.default_image_tag}"
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Pinned image to a stable tag", applied=True, details={"image": container["image"]})

    resources = ensure_dict(container, "resources")
    if patch_name == "add_default_requests":
        req = ensure_dict(resources, "requests")
        req.setdefault("cpu", "100m")
        req.setdefault("memory", "128Mi")
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Added default resource requests", applied=True, details={"requests": req})

    if patch_name == "add_default_limits":
        lim = ensure_dict(resources, "limits")
        lim.setdefault("cpu", "500m")
        lim.setdefault("memory", "512Mi")
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Added default resource limits", applied=True, details={"limits": lim})

    if patch_name == "add_default_readiness_probe":
        container.setdefault("readinessProbe", {
            "httpGet": {"path": "/ready", "port": 8080},
            "initialDelaySeconds": 5,
            "periodSeconds": 10,
        })
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Added default readiness probe", applied=True)

    if patch_name == "add_default_liveness_probe":
        container.setdefault("livenessProbe", {
            "httpGet": {"path": "/health", "port": 8080},
            "initialDelaySeconds": 10,
            "periodSeconds": 20,
        })
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Added default liveness probe", applied=True)

    sc = ensure_dict(container, "securityContext")
    if patch_name == "set_run_as_non_root":
        sc["runAsNonRoot"] = True
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Set runAsNonRoot=true", applied=True)

    if patch_name == "disable_privilege_escalation":
        sc["allowPrivilegeEscalation"] = False
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Set allowPrivilegeEscalation=false", applied=True)

    if patch_name == "disable_privileged":
        sc["privileged"] = False
        return FixAction(issue_code=finding.code, patch_name=patch_name, description="Set privileged=false", applied=True)

    return None
