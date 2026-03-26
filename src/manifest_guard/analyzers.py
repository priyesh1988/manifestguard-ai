from __future__ import annotations

from typing import Any

from .models import Finding
from .utils import containers_from_spec, pod_spec, resource_identity


def _signature(kind: str, code: str, container_name: str | None = None) -> str:
    return f"{kind}:{code}:{container_name or '-'}"


def analyze_document(file_path: str, doc: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    kind, name, namespace = resource_identity(doc)
    spec = pod_spec(doc)
    containers = containers_from_spec(spec)

    if spec and spec.get("automountServiceAccountToken", True):
        findings.append(Finding(
            code="AUTOMOUNT_SA_TOKEN",
            title="ServiceAccount token automount enabled",
            severity="medium",
            path="spec.automountServiceAccountToken",
            resource_kind=kind,
            resource_name=name,
            namespace=namespace,
            container_name=None,
            message="Disable automatic ServiceAccount token mounting unless required.",
            fixable=True,
            recommended_patch="disable_automount_sa_token",
            signature=_signature(kind, "AUTOMOUNT_SA_TOKEN"),
        ))

    if spec and spec.get("hostNetwork") is True:
        findings.append(Finding(
            code="HOST_NETWORK_ENABLED",
            title="hostNetwork is enabled",
            severity="high",
            path="spec.hostNetwork",
            resource_kind=kind,
            resource_name=name,
            namespace=namespace,
            container_name=None,
            message="hostNetwork expands blast radius and should usually be disabled.",
            fixable=True,
            recommended_patch="disable_host_network",
            signature=_signature(kind, "HOST_NETWORK_ENABLED"),
        ))

    for idx, container in enumerate(containers):
        cname = str(container.get("name", f"container-{idx}"))
        image = str(container.get("image", ""))
        if image.endswith(":latest") or ":" not in image:
            findings.append(Finding(
                code="IMAGE_LATEST_TAG",
                title="Mutable image tag detected",
                severity="high",
                path=f"containers[{idx}].image",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Pin images to an immutable version tag instead of latest or implicit tag.",
                fixable=True,
                recommended_patch="pin_image_tag",
                signature=_signature(kind, "IMAGE_LATEST_TAG", cname),
            ))

        resources = container.get("resources") or {}
        requests = resources.get("requests") or {}
        limits = resources.get("limits") or {}
        if "cpu" not in requests or "memory" not in requests:
            findings.append(Finding(
                code="MISSING_RESOURCE_REQUESTS",
                title="Missing resource requests",
                severity="high",
                path=f"containers[{idx}].resources.requests",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Set CPU and memory requests to improve scheduling and reliability.",
                fixable=True,
                recommended_patch="add_default_requests",
                signature=_signature(kind, "MISSING_RESOURCE_REQUESTS", cname),
            ))
        if "cpu" not in limits or "memory" not in limits:
            findings.append(Finding(
                code="MISSING_RESOURCE_LIMITS",
                title="Missing resource limits",
                severity="medium",
                path=f"containers[{idx}].resources.limits",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Set CPU and memory limits to contain noisy-neighbor risk.",
                fixable=True,
                recommended_patch="add_default_limits",
                signature=_signature(kind, "MISSING_RESOURCE_LIMITS", cname),
            ))

        if "readinessProbe" not in container:
            findings.append(Finding(
                code="MISSING_READINESS_PROBE",
                title="Missing readiness probe",
                severity="medium",
                path=f"containers[{idx}].readinessProbe",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Add a readiness probe so traffic is only sent when the app is ready.",
                fixable=True,
                recommended_patch="add_default_readiness_probe",
                signature=_signature(kind, "MISSING_READINESS_PROBE", cname),
            ))
        if "livenessProbe" not in container:
            findings.append(Finding(
                code="MISSING_LIVENESS_PROBE",
                title="Missing liveness probe",
                severity="medium",
                path=f"containers[{idx}].livenessProbe",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Add a liveness probe to restart wedged containers.",
                fixable=True,
                recommended_patch="add_default_liveness_probe",
                signature=_signature(kind, "MISSING_LIVENESS_PROBE", cname),
            ))

        sc = container.get("securityContext") or {}
        if sc.get("runAsNonRoot") is not True:
            findings.append(Finding(
                code="RUN_AS_NON_ROOT_MISSING",
                title="runAsNonRoot is not enforced",
                severity="high",
                path=f"containers[{idx}].securityContext.runAsNonRoot",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Set securityContext.runAsNonRoot to true.",
                fixable=True,
                recommended_patch="set_run_as_non_root",
                signature=_signature(kind, "RUN_AS_NON_ROOT_MISSING", cname),
            ))

        if sc.get("allowPrivilegeEscalation") is not False:
            findings.append(Finding(
                code="ALLOW_PRIV_ESC_NOT_FALSE",
                title="allowPrivilegeEscalation is not disabled",
                severity="high",
                path=f"containers[{idx}].securityContext.allowPrivilegeEscalation",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Disable privilege escalation unless explicitly required.",
                fixable=True,
                recommended_patch="disable_privilege_escalation",
                signature=_signature(kind, "ALLOW_PRIV_ESC_NOT_FALSE", cname),
            ))

        if sc.get("privileged") is True:
            findings.append(Finding(
                code="PRIVILEGED_CONTAINER",
                title="Privileged container enabled",
                severity="critical",
                path=f"containers[{idx}].securityContext.privileged",
                resource_kind=kind,
                resource_name=name,
                namespace=namespace,
                container_name=cname,
                message="Privileged containers should normally be avoided.",
                fixable=True,
                recommended_patch="disable_privileged",
                signature=_signature(kind, "PRIVILEGED_CONTAINER", cname),
            ))
    return findings
