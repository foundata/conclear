"""Host-independent identity for scanner evidence.

Trivy names the artifact it scanned by the local path it was given and repeats
that path in targets, SPDX document names and namespaces. Those paths describe
the release host, not the image, and would otherwise enter public SBOM
attestations and archives. Evidence therefore names the scanned subject by its
repository and content digest and keeps every other path relative to the run
workspace.
"""

from dataclasses import dataclass
from pathlib import Path

from conclear.parsing import object_value, string_value


@dataclass(frozen=True, slots=True)
class ScanIdentity:
    """What scanner output may say about where and what it scanned."""

    workspace_root: Path
    subject: str
    artifact_path: Path | None = None

    def rewrite_text(self, value: str) -> str:
        """Replace local artifact and workspace prefixes in one string."""
        if self.artifact_path is not None:
            artifact = str(self.artifact_path.absolute())
            if value == artifact or value.startswith(artifact + "/"):
                return self.subject + value[len(artifact) :]
            marker = value.find(artifact)
            if marker != -1:
                return value[:marker] + self.subject + value[marker + len(artifact) :]
        root = str(self.workspace_root.absolute())
        if value == root:
            return "."
        if value.startswith(root + "/"):
            return value[len(root) + 1 :]
        marker = value.find(root + "/")
        if marker != -1:
            return value[:marker] + value[marker + len(root) + 1 :]
        return value

    def rewrite(self, value: object) -> object:
        """Rewrite every string inside one JSON-like value, preserving structure."""
        if isinstance(value, str):
            return self.rewrite_text(value)
        if isinstance(value, list):
            return [self.rewrite(item) for item in value]
        if isinstance(value, dict):
            return {key: self.rewrite(item) for key, item in value.items()}
        return value


def neutralize_scan_report(value: object, identity: ScanIdentity) -> object:
    """Return a Trivy report that names the subject instead of local paths."""
    report = identity.rewrite(value)
    if isinstance(report, dict) and isinstance(report.get("ArtifactName"), str):
        report["ArtifactName"] = identity.subject
    return report


def neutralize_spdx_document(
    document: dict[str, object], identity: ScanIdentity
) -> dict[str, object]:
    """Return a validated SPDX document whose identities name the subject."""
    rewritten = object_value(identity.rewrite(document), "SPDX document")
    previous_name = string_value(document.get("name"), "SPDX document name")
    rewritten["name"] = identity.subject
    packages = rewritten.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if isinstance(package, dict) and package.get("name") in {
                previous_name,
                identity.subject,
            }:
                package["name"] = identity.subject
    return rewritten


def evidence_path(path: Path, root: Path) -> str:
    """Return a path for evidence: relative to ``root`` when inside it, else its name."""
    try:
        return str(path.absolute().relative_to(root.absolute()))
    except ValueError:
        return path.name
