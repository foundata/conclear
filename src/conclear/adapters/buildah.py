"""Rootless Buildah OCI-layout adapter."""

from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.adapters.parsing import json_value, object_value
from conclear.oci import OCIGraph, validate_layout
from conclear.process import OperationKind
from conclear.values import Platform


@dataclass(frozen=True, slots=True)
class BuildObservation:
    """Observed result of one platform build."""

    image_name: str
    layout_path: Path
    graph: OCIGraph
    build_arguments: tuple[tuple[str, str], ...]


class BuildahAdapter(ToolAdapter):
    """Build one platform using run-specific containers storage."""

    def info(self, *, root: Path, runroot: Path) -> dict[str, object]:
        """Validate access to one isolated rootless Buildah storage."""
        output = self._run(
            (
                "--root",
                str(root),
                "--runroot",
                str(runroot),
                "info",
                "--format",
                "json",
            ),
            timeout_seconds=120,
        ).stdout
        return object_value(
            json_value(output, label="Buildah info"), label="Buildah info"
        )

    def build(
        self,
        *,
        root: Path,
        runroot: Path,
        containerfile: Path,
        context: Path,
        platform: Platform,
        image_name: str,
        layout_path: Path,
        layout_reference: str,
        source_epoch: int,
        build_arguments: dict[str, str],
        auth_file: Path | None,
    ) -> BuildObservation:
        """Build and export a digest-preserving OCI image layout."""
        arguments: list[str] = [
            "--root",
            str(root),
            "--runroot",
            str(runroot),
            "build",
            "--format",
            "oci",
            "--platform",
            str(platform),
            "--timestamp",
            str(source_epoch),
            "--pull",
            "always",
            "--file",
            str(containerfile),
            "--tag",
            image_name,
        ]
        if auth_file is not None:
            arguments.extend(("--authfile", str(auth_file)))
        for name, value in sorted(build_arguments.items()):
            arguments.extend(("--build-arg", f"{name}={value}"))
        arguments.append(str(context))
        self._run(
            arguments,
            timeout_seconds=3600,
            operation=OperationKind.WRITE,
            secret_paths=(() if auth_file is None else (auth_file,)),
        )
        self._run(
            (
                "--root",
                str(root),
                "--runroot",
                str(runroot),
                "push",
                "--format",
                "oci",
                image_name,
                f"oci:{layout_path}:{layout_reference}",
            ),
            timeout_seconds=1800,
            operation=OperationKind.WRITE,
        )
        graph = validate_layout(layout_path, reference=layout_reference)
        return BuildObservation(
            image_name=image_name,
            layout_path=layout_path,
            graph=graph,
            build_arguments=tuple(sorted(build_arguments.items())),
        )

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        """Remove every image in one run-owned Buildah storage root."""
        self._run(
            ("--root", str(root), "--runroot", str(runroot), "rm", "--all"),
            timeout_seconds=300,
            operation=OperationKind.WRITE,
        )
        self._run(
            ("--root", str(root), "--runroot", str(runroot), "rmi", "--all"),
            timeout_seconds=300,
            operation=OperationKind.WRITE,
        )
