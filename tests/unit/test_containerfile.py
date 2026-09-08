from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import conclear.services.adoption_observation as adoption_module
from conclear.checks import analyze_containerfile, analyze_containerfile_source
from conclear.containerfile import (
    MAX_CONTAINERFILE_BYTES,
    Containerfile,
    load_containerfile,
    parse_containerfile,
)
from conclear.errors import InvalidInvocationError
from conclear.services.adoption_observation import observe_containerfile

REFERENCE = "quay.io/example/base:1@sha256:" + "a" * 64
PATH = Path("Containerfile")


def test_instructions_own_exact_image_input_spans_and_stage_resolution() -> None:
    content = (
        "# Multibyte comment: \u00e4\n"
        f"FROM --platform=linux/amd64 {REFERENCE} AS build\n"
        "FROM build AS runtime\n"
        "COPY --from='build' /source /destination\n"
        f'COPY --chown=1000:1000 --from="{REFERENCE}" ["/a b", "/c"]\n'
        f'RUN --mount="type=bind,from={REFERENCE},target=/a b" '
        "--mount=type=bind,from=build,target=/build echo ok\n"
        "RUN echo --mount=from=not-an-image\n"
        'COPY ["--from=not-an-image", "/destination"]\n'
        'LABEL note="--from=not-an-image"\n'
        "USER 1000\n"
        'ENTRYPOINT ["/app"]\n'
    ).encode()

    source = parse_containerfile(content, path=PATH)

    assert [item.reference for item in source.external_inputs] == [REFERENCE] * 3
    for item in source.external_inputs:
        assert content[item.span.start : item.span.end] == REFERENCE.encode()
    assert source.instructions[3].body == '["/a b", "/c"]'
    assert source.instructions[4].flags == (
        f"--mount=type=bind,from={REFERENCE},target=/a b",
        "--mount=type=bind,from=build,target=/build",
    )
    assert source.final_stage == source.instructions[1:]
    assert analyze_containerfile_source(source).external_references == (REFERENCE,)
    assert analyze_containerfile_source(source).findings == ()


def test_continuations_join_bytes_without_inserting_whitespace() -> None:
    content = (
        "FROM quay.io/example/ba\\\n"
        "# Comment inside an image token\n"
        "\n"
        f"se:1@sha256:{'a' * 64} AS build\n"
        "RUN echo hel\\ \t\n"
        "lo \\\n"
        "  world\n"
    ).encode()

    source = parse_containerfile(content, path=PATH)

    assert source.external_inputs[0].reference == REFERENCE
    assert source.instructions[0].line_number == 1
    assert source.instructions[0].end_line_number == 4
    assert source.instructions[1].body == "echo hello   world"
    span = source.external_inputs[0].span
    assert content[span.start : span.end].startswith(b"quay.io/example/ba\\\n")


@pytest.mark.parametrize("quote", ["'", '"', ""])
def test_multiple_external_mounts_and_add_from_are_structural(quote: str) -> None:
    content = (
        "FROM scratch AS base\n"
        f"ADD --from={quote}{REFERENCE}{quote} /a /b\n"
        f"RUN --mount=from={quote}{REFERENCE}{quote},target=/a "
        f"--mount=from={REFERENCE},target=/b true\n"
        "COPY --from=0 /a /b\n"
        "RUN --mount=from=0,target=/a true\n"
    ).encode()
    source = parse_containerfile(content, path=PATH)

    assert [item.reference for item in source.external_inputs] == [REFERENCE] * 3
    assert all(
        source.instructions[index].image_inputs[0].numeric_stage for index in (3, 4)
    )
    assert (
        sum(
            finding.check_id == "CC0104"
            for finding in analyze_containerfile_source(source).findings
        )
        == 2
    )


def test_builder_flag_terminator_and_quoted_shell_text_are_not_inputs() -> None:
    source = parse_containerfile(
        b'FROM scratch\nRUN -- echo "--mount=from=example"\n'
        b'COPY -- "--from=example" /destination\n',
        path=PATH,
    )
    assert source.external_inputs == ()
    assert source.instructions[1].body == 'echo "--mount=from=example"'
    assert source.instructions[2].body == '"--from=example" /destination'


def test_escaped_flag_values_keep_original_source_positions() -> None:
    content = (
        "FROM scratch\n"
        f"COPY --from=quay.io/ex\\ample/base:1@sha256:{'a' * 64} /a /b\n"
        "RUN --network=none echo ok\n"
    ).encode()
    source = parse_containerfile(content, path=PATH)
    (operand,) = source.external_inputs
    assert operand.reference == REFERENCE
    assert (
        content[operand.span.start : operand.span.end]
        == REFERENCE.replace("example", "ex\\ample").encode()
    )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"FROM\n", "Malformed FROM"),
        (b"FROM scratch AS\n", "Malformed FROM"),
        (b"$invalid\n", "Malformed instruction"),
        (b"RUN echo \\\n", "Unterminated continuation"),
        (b"\\\n", "Unterminated continuation"),
        (b'COPY --from="base /a /b\n', "Unterminated builder flag quote"),
        (b"COPY --from=base --from=other /a /b\n", "Duplicate --from"),
        (b"RUN --mount=from=a,from=b true\n", "Duplicate mount from"),
        (b"RUN --mount=from= true\n", "Empty image input"),
        (b"COPY --from= /a /b\n", "Empty image input"),
        (b"# escape=`\nFROM scratch\n", "Non-default parser directive"),
        (b"# platform=windows\nFROM scratch\n", "Non-default parser directive"),
        (b"RUN <<EOF\necho ok\nEOF\n", "Heredoc syntax is not supported"),
        (b"COPY <<EOF /file\ncontents\nEOF\n", "Heredoc syntax is not supported"),
        (b"ONBUILD COPY --from=hidden /a /b\n", "Unsupported instruction ONBUILD"),
    ],
)
def test_unsupported_or_ambiguous_syntax_has_an_explicit_boundary(
    content: bytes, message: str
) -> None:
    with pytest.raises(InvalidInvocationError, match=message) as caught:
        parse_containerfile(content, path=PATH)
    assert "Containerfile:1" in str(caught.value)
    assert "ARCHITECTURE.md" in str(caught.value)


def test_default_directive_bom_crlf_and_unicode_line_separator() -> None:
    content = (
        "\ufeff# escape=\\\r\n"
        f"FROM {REFERENCE}\r\n"
        'LABEL note="one\u2028two"\r\n'
        "USER 1000\r\n"
        'CMD ["<<literal"]\r\n'
    ).encode()
    source = parse_containerfile(content, path=PATH)
    assert len(source.instructions) == 4
    assert source.instructions[1].body == 'note="one\u2028two"'
    span = source.external_inputs[0].span
    assert content[span.start : span.end] == REFERENCE.encode()
    assert [
        item.check_id for item in analyze_containerfile_source(source).findings
    ] == ["CC0101", "CC0101"]


@pytest.mark.parametrize(
    "command",
    ["[]", "[1]", "{}", '[["/app"]]', "/app", "[" * 2000, "[" + "1" * 5000 + "]"],
)
def test_invalid_exec_arrays_are_consistent_between_check_and_adopt(
    tmp_path: Path, command: str
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        f"FROM scratch\nUSER 1000\nENTRYPOINT {command}\n", encoding="utf-8"
    )
    source = load_containerfile(path)
    assert source.instructions[-1].exec_command is None
    assert any(
        item.check_id == "CC0111" for item in analyze_containerfile(path).findings
    )
    assert (
        observe_containerfile(tmp_path, path, image_id="app").entrypoint.form == "shell"
    )


def test_final_stage_does_not_inherit_observations_from_unrelated_stage(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        'FROM scratch AS build\nUSER 1000\nENTRYPOINT ["/sbin/init"]\n'
        "LABEL a=b\nVOLUME /data\nSTOPSIGNAL SIGQUIT\nFROM scratch\nUSER 1000\n",
        encoding="utf-8",
    )
    observed = observe_containerfile(tmp_path, path, image_id="app")
    assert observed.entrypoint.form == "missing"
    assert observed.labels == ()
    assert observed.volumes == ()
    assert observed.stop_signal is None
    assert any(item.check_id == "CC0111" for item in observed.findings)


def test_parsed_source_survives_later_file_changes(tmp_path: Path) -> None:
    path = tmp_path / "Containerfile"
    original = f'FROM {REFERENCE}\nUSER 1000\nCMD ["/app"]\n'.encode()
    path.write_bytes(original)
    source = load_containerfile(path)
    path.write_bytes(b"FROM scratch\n")
    assert source.content == original
    assert analyze_containerfile_source(source).findings == ()
    assert analyze_containerfile_source(source).external_references == (REFERENCE,)


def test_adoption_checks_the_same_snapshot_it_observed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(f'FROM {REFERENCE}\nUSER 1000\nCMD ["/app"]\n', encoding="utf-8")
    source = load_containerfile(path)

    def load_then_mutate(selected: Path) -> Containerfile:
        assert selected == path
        selected.write_bytes(b"FROM scratch\n")
        return source

    monkeypatch.setattr(adoption_module, "load_containerfile", load_then_mutate)
    observation = observe_containerfile(tmp_path, path, image_id="app")
    assert observation.user.uid == 1000
    assert observation.findings == ()
    assert observation.external_references[0].reference == REFERENCE


def test_invalid_utf8_and_oversize_input_fail_with_bounded_errors(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Containerfile"
    path.write_bytes(b"FROM \xff\n")
    with pytest.raises(InvalidInvocationError, match="not valid UTF-8"):
        load_containerfile(path)
    assert analyze_containerfile(path).findings[0].check_id == "CC0101"
    with pytest.raises(InvalidInvocationError, match="byte limit"):
        parse_containerfile(b"#" * (MAX_CONTAINERFILE_BYTES + 1), path=PATH)


@given(
    prefix=st.text(alphabet="abcdef\u00e4\u2028", max_size=40),
    whitespace=st.sampled_from([" ", "\t", " \\\n  ", " \\\n# ignored\n\n\t"]),
    quote=st.sampled_from(["", '"', "'"]),
)
def test_reference_spans_round_trip_across_layouts(
    prefix: str, whitespace: str, quote: str
) -> None:
    content = (
        f"# {prefix}\nFROM scratch\nCOPY{whitespace}"
        f"--from={quote}{REFERENCE}{quote}{whitespace}/source /destination\n"
    ).encode()
    source = parse_containerfile(content, path=PATH)
    (operand,) = source.external_inputs
    assert operand.reference == REFERENCE
    assert content[operand.span.start : operand.span.end] == REFERENCE.encode()
