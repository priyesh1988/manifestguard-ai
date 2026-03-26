# Architecture

ManifestGuard follows a deterministic pipeline:

1. Load Kubernetes YAML documents.
2. Detect findings with built-in analyzers.
3. Choose a recommended or historically successful patch.
4. Apply safe in-memory fixes.
5. Optionally write manifests back to disk.
6. Persist fix outcomes into the remediation history store.

The learning layer is intentionally lightweight: it ranks future patch choices using prior success rates instead of making opaque model decisions.
