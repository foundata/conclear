from typing import Any

import pytest

from conclear.errors import OperationalError
from conclear.spdx import validate_spdx_document


def document(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "app",
        "documentNamespace": "https://example.invalid/spdx/app",
        "creationInfo": {
            "creators": ["Tool: trivy-0.69.3"],
            "created": "2026-01-01T00:00:00Z",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-app",
                "name": "app",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
        ],
        "files": [{"SPDXID": "SPDXRef-File-bin", "fileName": "/usr/bin/app"}],
        "documentDescribes": ["SPDXRef-Package-app"],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-app",
            }
        ],
    }
    value.update(changes)
    return value


def test_complete_document_is_accepted() -> None:
    value = document()
    assert validate_spdx_document(value, label="SBOM") is value


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"spdxVersion": "SPDX-2.2"}, "not an SPDX 2.3 document"),
        ({"dataLicense": "MIT"}, "invalid SPDX data license"),
        ({"SPDXID": "SPDXRef-OTHER"}, "invalid document SPDX identifier"),
        ({"name": ""}, "name must be a non-empty string"),
        ({"documentNamespace": "not a uri"}, "not a URI"),
        ({"creationInfo": []}, "creation info must be a JSON object"),
        (
            {"creationInfo": {"creators": [], "created": "2026-01-01T00:00:00Z"}},
            "creators",
        ),
        (
            {
                "creationInfo": {
                    "creators": ["Robot"],
                    "created": "2026-01-01T00:00:00Z",
                }
            },
            "creators are malformed",
        ),
        (
            {
                "creationInfo": {
                    "creators": ["Tool: x"],
                    "created": "2026-01-01T00:00:00",
                }
            },
            "must use UTC",
        ),
        (
            {"creationInfo": {"creators": ["Tool: x"], "created": "yesterdayZ"}},
            "creation time is malformed",
        ),
        ({"packages": {}}, "packages must be an array"),
        ({"packages": [1]}, "packages element must be a JSON object"),
        ({"packages": [{"SPDXID": "bad id", "name": "x"}]}, "identifier is malformed"),
        (
            {"packages": [{"SPDXID": "SPDXRef-DOCUMENT", "name": "x"}]},
            "repeats SPDX identifier",
        ),
        (
            {
                "packages": [
                    {"SPDXID": "SPDXRef-P", "name": "", "downloadLocation": "x"}
                ]
            },
            "package name",
        ),
        (
            {
                "packages": [
                    {"SPDXID": "SPDXRef-P", "name": "x", "downloadLocation": ""}
                ]
            },
            "download location",
        ),
        (
            {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-P",
                        "name": "x",
                        "downloadLocation": "x",
                        "filesAnalyzed": "no",
                    }
                ]
            },
            "filesAnalyzed must be boolean",
        ),
        ({"files": [{"SPDXID": "SPDXRef-F"}]}, "file name"),
        ({"documentDescribes": ["SPDXRef-Missing"]}, "documentDescribes is malformed"),
        ({"relationships": {}}, "relationships must be an array"),
        (
            {"relationships": [{"spdxElementId": "SPDXRef-DOCUMENT"}]},
            "relationship relationshipType",
        ),
    ],
    ids=[
        "version",
        "license",
        "document-id",
        "name",
        "namespace",
        "creation-info",
        "empty-creators",
        "creator-shape",
        "created-not-utc",
        "created-malformed",
        "packages-shape",
        "package-element",
        "package-id",
        "duplicate-id",
        "package-name",
        "download-location",
        "files-analyzed",
        "file-name",
        "describes",
        "relationships-shape",
        "relationship-fields",
    ],
)
def test_malformed_documents_are_operational_failures(
    changes: dict[str, Any], message: str
) -> None:
    with pytest.raises(OperationalError, match=message):
        validate_spdx_document(document(**changes), label="SBOM")


def test_document_must_be_an_object() -> None:
    with pytest.raises(OperationalError, match="must be a JSON object"):
        validate_spdx_document([], label="SBOM")
