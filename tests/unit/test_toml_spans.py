import tomllib

import pytest

from conclear.errors import InvalidInvocationError
from conclear.toml_spans import locate_string_values


def _by_path(data: bytes) -> dict[tuple[str | int, ...], tuple[int, int, str]]:
    return {
        item.path: (item.start, item.end, item.value)
        for item in locate_string_values(data)
    }


def test_array_of_tables_paths_index_each_image_and_its_pins() -> None:
    data = b"""schema_version = 1

[project]
name = "example"

[[images]]
id = "runtime"

[images.runtime]
memory = "256MiB"

[[images.pins]]
reference = "docker.io/library/debian:13-slim@sha256:aaaa"
tag_intent = "moving-release-line"

[[images.pins]]
reference = 'quay.io/example/tool:1@sha256:bbbb'
tag_intent = "immutable-version"

[[images]]
id = "generator"

[[images.pins]]
reference = "docker.io/library/debian:13-slim@sha256:aaaa"
tag_intent = "moving-release-line"
"""
    located = _by_path(data)

    assert located[("project", "name")][2] == "example"
    assert located[("images", 0, "id")][2] == "runtime"
    assert located[("images", 0, "runtime", "memory")][2] == "256MiB"
    assert located[("images", 0, "pins", 0, "reference")][2].endswith("aaaa")
    assert located[("images", 0, "pins", 1, "reference")][2].endswith("bbbb")
    assert located[("images", 1, "id")][2] == "generator"
    assert located[("images", 1, "pins", 0, "reference")][2].endswith("aaaa")
    for start, end, value in located.values():
        assert data[start:end].decode("utf-8") == value


def test_inline_tables_and_nested_arrays_receive_indexed_paths() -> None:
    data = b"""[[images]]
id = "app"
pins = [
  { reference = "quay.io/a/b:1@sha256:aaaa", tag_intent = "immutable-version" },
  { reference = "quay.io/a/c:2@sha256:bbbb", tag_intent = "moving-release-line" },
]
matrix = [["x"], ["y", "z"]]
"""
    located = _by_path(data)

    assert located[("images", 0, "pins", 0, "reference")][2].endswith("aaaa")
    assert located[("images", 0, "pins", 1, "reference")][2].endswith("bbbb")
    assert located[("images", 0, "matrix", 0, 0)][2] == "x"
    assert located[("images", 0, "matrix", 1, 1)][2] == "z"


def test_comments_dotted_and_quoted_keys_and_byte_offsets() -> None:
    data = (
        '# reference = "quay.io/comment/only:1@sha256:cccc" é\n'
        'title = "has # hash" # trailing "comment"\n'
        'a.b = "dotted"\n'
        '"quoted key" = "value"\n'
        "[table.sub]\n"
        'escaped = "say \\"hi\\""\n'
    ).encode()
    located = _by_path(data)

    assert ("reference",) not in located
    assert located[("title",)][2] == "has # hash"
    assert located[("a", "b")][2] == "dotted"
    assert located[("quoted key",)][2] == "value"
    start, end, value = located[("table", "sub", "escaped")]
    assert value == 'say "hi"'
    assert data[start:end] == b'say \\"hi\\"'
    assert tomllib.loads(data.decode("utf-8"))["table"]["sub"]["escaped"] == value


def test_multi_line_strings_are_skipped_without_breaking_structure() -> None:
    data = b'''text = """
multi "line"
"""
after = "value"
literal = \'\'\'raw
lines\'\'\'
last = 'done'
'''
    located = _by_path(data)

    assert ("text",) not in located
    assert ("literal",) not in located
    assert located[("after",)][2] == "value"
    assert located[("last",)][2] == "done"


def test_non_string_values_and_dates_are_skipped() -> None:
    data = b"""number = 1
flag = true
when = 1979-05-27 07:32:00Z
[section]
list = [1, 2, "three"]
"""
    located = _by_path(data)

    assert list(located) == [("section", "list", 2)]
    assert located[("section", "list", 2)][2] == "three"


@pytest.mark.parametrize(
    "data",
    [
        b'name = "unterminated\n',
        b"[unclosed\nname = 'x'\n",
        b"name = \n",
        b'name = "a" "b"\n',
        b"= 'x'\n",
        b"[[a]]\n[a.b\n",
        b"\xff\xfe = 'x'\n",
    ],
)
def test_malformed_documents_are_rejected(data: bytes) -> None:
    with pytest.raises(InvalidInvocationError):
        locate_string_values(data)


def test_located_values_match_tomllib_for_a_realistic_configuration() -> None:
    data = b"""schema_version = 1

[project]
name = "oci-openldap-declarative"
source = "https://github.com/foundata/oci-openldap-declarative"

[[images]]
id = "runtime"
repository = "quay.io/foundata/openldap-declarative"
platforms = ["linux/amd64"]
arm64_omission_reason = "2026-09-03: no arm64 worker."

[images.test]
dependencies = ["generator"]

[[images.test.preparations]]
name = "create"
image = "generator"
command = ["/bin/sh", "-c", "printf '%s\\\\n' 'x' > /output/y"]
mounts = [{ name = "credentials", target = "/output", read_only = false }]

[images.test.launch]
environment = { LDAP_EXPECTED_SERVICE_ID = "example-app" }

[[images.pins]]
reference = "docker.io/library/debian:13-slim@sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f"
tag_intent = "moving-release-line"

[images.release]
immutable_tags = ["{version}"]
moving_tags = ["stable"]
"""
    parsed = tomllib.loads(data.decode("utf-8"))
    for item in locate_string_values(data):
        current: object = parsed
        for part in item.path:
            assert isinstance(current, dict | list)
            current = current[part]  # type: ignore[index]
        assert current == item.value
