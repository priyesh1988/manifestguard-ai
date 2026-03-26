# ManifestGuard

**ManifestGuard** is a production-oriented Kubernetes manifest remediation product that finds risky configuration patterns, applies deterministic safe fixes, and remembers what worked before.

It is designed for platform teams that want to shift remediation left: catch issues before admission, standardize safe corrections, and build an operational memory of repeated mistakes across repositories and teams.

## Why customers care

Most manifest scanners stop at detection. ManifestGuard goes further:

- **Detects** common Kubernetes reliability and security issues in YAML before deployment.
- **Fixes** safe issues automatically or in dry-run mode.
- **Learns** from previous remediation outcomes using a built-in history store.
- **Reports** findings and actions in machine-readable JSON for CI/CD.
- **Exports** starter Kyverno policies so successful guardrails can be promoted into cluster policy.

## What it finds today

- mutable or implicit image tags
- missing CPU and memory requests
- missing CPU and memory limits
- missing readiness probes
- missing liveness probes
- missing `runAsNonRoot`
- `allowPrivilegeEscalation` not set to `false`
- privileged containers enabled
- `automountServiceAccountToken` left enabled
- `hostNetwork: true`

## What it fixes automatically

ManifestGuard only applies **deterministic, low-ambiguity** remediations by default.

- pins image tags to a configured safe version
- adds default resource requests and limits
- adds default readiness and liveness probes
- enforces `runAsNonRoot: true`
- sets `allowPrivilegeEscalation: false`
- disables privileged mode
- disables ServiceAccount token automount
- disables `hostNetwork`

## How the learning loop works

ManifestGuard does not rely on opaque AI by default. Its learning model is operational and auditable:

1. normalize each issue into a reusable signature
2. record the patch choice used for that signature
3. record whether the action succeeded
4. prefer the historically best patch next time the same pattern appears

This makes the system predictable enough for enterprise platform teams while still improving from repeated use.

## Product flow

```text
YAML manifests
    -> analyzers
    -> structured findings
    -> patch selection
    -> history-informed remediation
    -> JSON report / optional file rewrite
    -> remediation memory store
```

## Customer-ready capabilities included

- CLI for local use and CI pipelines
- SQLite remediation history store
- configurable defaults via `manifestguard.yaml`
- GitHub Actions CI workflow
- Docker image build support
- pre-commit configuration
- contributor, security, and issue templates
- starter Kyverno policy export
- example manifests and test suite

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

manifest-guard scan examples/
manifest-guard fix examples/ --report-json dist/report.json
manifest-guard fix examples/ --write
manifest-guard export-kyverno --output dist/kyverno/manifestguard-policies.yaml
```

## Example output

```bash
manifest-guard fix examples/ --report-json dist/report.json
```

You get:
- a summary of findings and fixed items in the terminal
- a JSON report for pipeline consumption
- an updated remediation history database under `.manifestguard/`

## Configuration

`manifestguard.yaml`

```yaml
manifestGuard:
  dbPath: .manifestguard/history.sqlite3
  defaultImageTag: 1.0.0
  enableLearning: true
```

## Suggested GitHub usage

### Pull request gate

```bash
manifest-guard scan k8s/ --fail-on high
```

### Auto-fix job with artifact output

```bash
manifest-guard fix k8s/ --report-json dist/report.json
```

### Controlled in-place remediation

```bash
manifest-guard fix k8s/ --write
```

## Why this design is aligned with the ecosystem

Kubernetes documents Server-Side Apply as the declarative mechanism for managing resources, and the API concepts docs note that Server-Side Apply has superseded Strategic Merge Patch for apply-style workflows. Kyverno supports validation, mutation, generation, cleanup, and image verification policies, while Gatekeeper provides validating and mutating admission controls. Trivy also supports Kubernetes-focused configuration and misconfiguration scanning. ManifestGuard complements these by operating **before** cluster admission and by keeping a reusable remediation memory across runs. citeturn994019search0turn994019search16turn994019search9turn994019search10turn994019search15

## Recommended deployment model

For most teams:

1. start in scan-only mode in CI
2. review JSON reports and default fixes
3. enable auto-fix in pull requests
4. promote repeated controls into Kyverno or Gatekeeper policies
5. keep ManifestGuard as the pre-admission remediation and memory layer

## Repository layout

```text
src/manifest_guard/
  analyzers.py        # built-in finding logic
  cli.py              # CLI commands
  config.py           # config loading
  engine.py           # scan/fix pipeline
  fixes.py            # deterministic patching
  memory.py           # remediation history store
  policy_export.py    # Kyverno policy export
  reporting.py        # JSON output helpers
  utils.py            # YAML and manifest helpers
examples/
docs/
tests/
.github/
```

## Production notes

- Default fixes are intentionally conservative.
- The learning store records issue signatures and outcomes, not secret values.
- Use PR-based workflows before enabling direct writes in critical repositories.
- The included Dockerfile and CI workflow are ready for GitHub-based delivery pipelines.

## Roadmap already prepared in this repo structure

- shared PostgreSQL memory backend for multi-team learning
- SARIF export for code scanning integrations
- PR comment bot for fix explanation and approval hints
- richer policy export packs for Kyverno and Gatekeeper
- optional LLM explanation layer on top of deterministic fixes

## License

Apache-2.0
