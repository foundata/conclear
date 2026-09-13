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
                "ARG IMAGE_CREATED\nARG IMAGE_REVISION\nARG IMAGE_VERSION\n"
                'LABEL org.opencontainers.image.source="https://foundata.com/en/projects/example/#source" \\\n'
                '      org.opencontainers.image.title="Example" \\\n'
                '      org.opencontainers.image.created="${IMAGE_CREATED}" \\\n'
                '      org.opencontainers.image.revision="${IMAGE_REVISION}" \\\n'
                '      org.opencontainers.image.version="${IMAGE_VERSION}"\n'
                "USER 10001:10001\n"
                "[invalid]"
            ).replace("[invalid]", 'ENTRYPOINT ["/app"]\n'),
            encoding="utf-8",
        )
        (root / ".containerignore").write_text(
            "**/.git/\n**/.env*\n**/*.key\n**/*.pem\n**/.venv/\n**/venv/\n",
            encoding="utf-8",
        )
        (root / "conclear.toml").write_text(
            """schema_version = 1

[project]
name = "example"
source = "https://foundata.com/en/projects/example/#source"

[[images]]
id = "app"
repository = "quay.io/example/app"
platforms = ["linux/amd64"]

[images.release]
version_tags = ["{version}"]
moving_tags = ["stable"]

[images.runtime]
profile = "service"
user = 10001
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]

[[images.pins]]
reference = "quay.io/example/base:1"
tag_intent = "immutable-version"
""",
            encoding="utf-8",
        )
        return root

    return create
