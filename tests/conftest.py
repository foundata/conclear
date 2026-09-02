from collections.abc import Callable
from pathlib import Path

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "/tests/unit/" in str(item.path):
            item.add_marker(pytest.mark.unit)


@pytest.fixture
def repository_factory(tmp_path: Path) -> Callable[..., Path]:
    def create(*, containerfile: str | None = None) -> Path:
        root = tmp_path / "repository"
        root.mkdir()
        (root / "Containerfile").write_text(
            containerfile
            or (
                "FROM quay.io/example/base:1@sha256:" + "a" * 64 + " AS runtime\n"
                'LABEL org.opencontainers.image.source="https://github.com/example/app"\n'
                "USER 10001:10001\n"
                "[invalid]"
            ).replace("[invalid]", 'ENTRYPOINT ["/app"]\n'),
            encoding="utf-8",
        )
        (root / ".containerignore").write_text(
            "**/.git/\n**/.env*\n**/*.key\n**/*.pem\n**/.venv/\n**/venv/\n",
            encoding="utf-8",
        )
        digest = "a" * 64
        (root / "conclear.toml").write_text(
            f"""schema_version = 1

[project]
name = "example"
source = "https://github.com/example/app.git"

[[images]]
id = "app"
containerfile = "Containerfile"
context = "."
repository = "quay.io/example/app"
platforms = ["linux/amd64"]
native_test_platforms = ["linux/amd64"]
arm64_omission_reason = "The dependency is not available for arm64."

[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "service"
user = 10001
read_only = true
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]

[[images.pins]]
reference = "quay.io/example/base:1@sha256:{digest}"
tag_intent = "immutable-version"
""",
            encoding="utf-8",
        )
        return root

    return create
