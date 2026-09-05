import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conclear.errors import InvalidInvocationError
from conclear.values import (
    Digest,
    OCIReference,
    Platform,
    candidate_tag,
)


def test_reference_requires_fully_qualified_registry() -> None:
    with pytest.raises(InvalidInvocationError, match="fully qualified"):
        OCIReference.parse("fedora:latest")


def test_reference_parses_tag_and_digest() -> None:
    digest = "sha256:" + "a" * 64
    reference = OCIReference.parse(
        f"quay.io/fedora/fedora-minimal:43@{digest}",
        require_tag=True,
        require_digest=True,
    )
    assert reference.registry == "quay.io"
    assert reference.repository == "fedora/fedora-minimal"
    assert reference.tag == "43"
    assert reference.digest == Digest(digest)
    assert str(reference) == f"quay.io/fedora/fedora-minimal:43@{digest}"


@given(st.text(alphabet=string.whitespace + "/:@", min_size=1, max_size=30))
def test_reference_parser_rejects_separator_noise(value: str) -> None:
    with pytest.raises(InvalidInvocationError):
        OCIReference.parse(value, require_digest=True)


@given(
    st.sampled_from(["linux", "freebsd"]),
    st.sampled_from(["amd64", "arm64", "arm"]),
    st.one_of(st.none(), st.sampled_from(["v6", "v7", "v8"])),
)
def test_platform_round_trip(
    operating_system: str,
    architecture: str,
    variant: str | None,
) -> None:
    parts = [operating_system, architecture]
    if variant is not None:
        parts.append(variant)
    value = "/".join(parts)
    assert str(Platform.parse(value)) == value


def test_platforms_sort_with_and_without_variants() -> None:
    platforms = [
        Platform.parse("linux/arm64/v8"),
        Platform.parse("linux/amd64/v3"),
        Platform.parse("linux/arm64"),
        Platform.parse("linux/amd64"),
    ]

    assert [str(item) for item in sorted(platforms)] == [
        "linux/amd64",
        "linux/amd64/v3",
        "linux/arm64",
        "linux/arm64/v8",
    ]
    assert Platform.parse("linux/amd64") <= Platform.parse("linux/amd64")
    assert Platform.parse("linux/arm64") > Platform.parse("linux/amd64/v3")


def test_arm64_default_variant_matches_explicit_v8_only() -> None:
    implicit = Platform.parse("linux/arm64")

    assert implicit.semantically_matches(Platform.parse("linux/arm64/v8"))
    assert not implicit.semantically_matches(Platform.parse("linux/arm64/v9"))
    assert not implicit.semantically_matches(Platform.parse("freebsd/arm64/v8"))


def test_candidate_tag_uses_required_version_first_shape() -> None:
    assert (
        candidate_tag(
            version="1.2.3",
            run_id="01k3z8h6v4n7c2m9p5q1r0s8tx",
            source_revision="a" * 40,
        )
        == "1.2.3-candidate.01k3z8h6v4n7c2m9p5q1r0s8tx.gaaaaaaaa"
    )
