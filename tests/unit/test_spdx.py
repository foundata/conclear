import pytest

from conclear.errors import OperationalError
from conclear.spdx import validate_spdx_document


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
    assert validate_spdx_document(_document(), label="SBOM")["name"] == "example"


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
        validate_spdx_document(document, label="SBOM")


def test_spdx_document_rejects_duplicate_element_identifiers() -> None:
    document = _document()
    packages = document["packages"]
    assert isinstance(packages, list)
    packages.append(dict(packages[0]))

    with pytest.raises(OperationalError, match="repeats SPDX identifier"):
        validate_spdx_document(document, label="SBOM")
