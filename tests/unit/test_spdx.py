import pytest

from conclear.attestations import SPDX_DOCUMENT_TYPE
from conclear.errors import OperationalError
from conclear.spdx import SPDX_2_3, SpdxFormat, validate_spdx_document


def _document() -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "example",
        "documentNamespace": "https://example.invalid/spdx/example",
        "creationInfo": {
            "creators": ["Tool: trivy-0.69.3"],
            "created": "2026-08-31T12:00:00Z",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-openssl",
                "name": "openssl",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        ],
        "documentDescribes": ["SPDXRef-Package-openssl"],
    }


def test_spdx_document_validates_mandatory_creation_and_package_fields() -> None:
    assert (
        validate_spdx_document(_document(), label="SBOM", spdx_version="SPDX-2.3")[
            "name"
        ]
        == "example"
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("dataLicense", "MIT", "data license"),
        ("SPDXID", "SPDXRef-Other", "document SPDX identifier"),
        ("documentNamespace", "not a URI", "namespace"),
    ],
)
def test_spdx_document_rejects_invalid_mandatory_field(
    field: str, value: str, message: str
) -> None:
    document = _document()
    document[field] = value

    with pytest.raises(OperationalError, match=message):
        validate_spdx_document(document, label="SBOM", spdx_version="SPDX-2.3")


def test_spdx_document_rejects_duplicate_element_identifiers() -> None:
    document = _document()
    packages = document["packages"]
    assert isinstance(packages, list)
    packages.append(dict(packages[0]))

    with pytest.raises(OperationalError, match="repeats SPDX identifier"):
        validate_spdx_document(document, label="SBOM", spdx_version="SPDX-2.3")


def test_records_without_format_fields_read_as_spdx_2_3_under_legacy_type() -> None:
    legacy = SpdxFormat(SPDX_2_3, SPDX_DOCUMENT_TYPE)

    assert SpdxFormat.from_record(None, label="release SBOM") == legacy
    assert (
        SpdxFormat.from_record(
            {"digest": "sha256:" + "0" * 64, "spdxVersion": "SPDX-2.3"},
            label="qualification SBOM",
        )
        == legacy
    )
    assert legacy.predicate_type == "https://spdx.dev/Document"


def test_recorded_format_is_read_verbatim() -> None:
    recorded = SpdxFormat.from_record(
        {
            "spdxVersion": "SPDX-2.3",
            "predicateType": "https://example.invalid/predicates/spdx/v1",
        },
        label="release SBOM",
    )

    assert recorded == SpdxFormat(
        "SPDX-2.3", "https://example.invalid/predicates/spdx/v1"
    )
    assert recorded.to_dict() == {
        "spdxVersion": "SPDX-2.3",
        "predicateType": "https://example.invalid/predicates/spdx/v1",
    }


def test_recorded_format_rejects_a_non_uri_predicate_type() -> None:
    with pytest.raises(OperationalError, match="HTTPS URI"):
        SpdxFormat.from_record(
            {"spdxVersion": "SPDX-2.3", "predicateType": "spdxjson"},
            label="release SBOM",
        )


def test_attached_format_follows_the_version_table() -> None:
    assert SpdxFormat.for_version("SPDX-2.3").to_dict() == {
        "spdxVersion": "SPDX-2.3",
        "predicateType": "https://spdx.dev/Document",
    }
    with pytest.raises(OperationalError, match="Unsupported SPDX version"):
        SpdxFormat.for_version("SPDX-3.0.1")
