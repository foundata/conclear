"""Runtime validation for retained SPDX JSON documents and their recorded format."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Self
from urllib.parse import urlsplit

from conclear.attestations import SPDX_DOCUMENT_TYPE
from conclear.errors import OperationalError
from conclear.parsing import object_value, string_value

SPDX_2_3 = "SPDX-2.3"
SPDX_PREDICATE_TYPES: Mapping[str, str] = MappingProxyType(
    {SPDX_2_3: SPDX_DOCUMENT_TYPE}
)
"""The predicate type each supported SPDX version is attested under.

Cosign resolves its `--type spdxjson` alias to `https://spdx.dev/Document`.
ConClear hands Cosign the URI itself, so the type written into a record is the
type that was attached and `cosign verify-attestation --type spdxjson` keeps
matching releases attested under the legacy URI.
"""

_SPDX_IDENTIFIER = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
_CREATOR = re.compile(r"^(?:Person|Organization|Tool):\s*\S.*$")


@dataclass(frozen=True, slots=True)
class SpdxFormat:
    """The SPDX version of an SBOM and the predicate type it is attested under."""

    version: str
    predicate_type: str

    @classmethod
    def for_version(cls, version: str) -> Self:
        """Pair a supported SPDX version with the predicate type ConClear attaches."""
        predicate_type = SPDX_PREDICATE_TYPES.get(version)
        if predicate_type is None:
            raise OperationalError(f"Unsupported SPDX version {version}")
        return cls(version, predicate_type)

    @classmethod
    def from_record(cls, value: object, *, label: str) -> Self:
        """Read the format a record names for its SBOM.

        Records written before the format was recorded carry SPDX 2.3 under the
        legacy predicate type, so both fields default on read. New records name
        both fields explicitly.
        """
        if value is None:
            return cls(SPDX_2_3, SPDX_DOCUMENT_TYPE)
        item = object_value(value, label)
        version = string_value(
            item.get("spdxVersion", SPDX_2_3), f"{label} SPDX version"
        )
        predicate_type = string_value(
            item.get("predicateType", SPDX_DOCUMENT_TYPE),
            f"{label} predicate type",
        )
        if not predicate_type.startswith("https://"):
            raise OperationalError(f"{label} predicate type must be an HTTPS URI")
        return cls(version, predicate_type)

    def to_dict(self) -> dict[str, object]:
        """Serialize the format as the record fields readers follow."""
        return {"spdxVersion": self.version, "predicateType": self.predicate_type}


def validate_spdx_document(
    value: object, *, label: str, spdx_version: str
) -> dict[str, object]:
    """Validate a document against the SPDX version its record names.

    The declared `spdxVersion` must equal the recorded version; a document of
    another version, including an SPDX 3 JSON-LD document that declares no
    `spdxVersion` at all, is rejected before any structural check. Structural
    validation covers SPDX 2.3 only.
    """
    document = object_value(value, label)
    if document.get("spdxVersion") != spdx_version:
        raise OperationalError(
            f"{label} does not declare the recorded SPDX version {spdx_version}"
        )
    if spdx_version != SPDX_2_3:
        raise OperationalError(
            f"{label} names SPDX version {spdx_version}, "
            "which ConClear does not validate"
        )
    if document.get("dataLicense") != "CC0-1.0":
        raise OperationalError(f"{label} has an invalid SPDX data license")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise OperationalError(f"{label} has an invalid document SPDX identifier")
    string_value(document.get("name"), f"{label} name")
    namespace = string_value(
        document.get("documentNamespace"), f"{label} document namespace"
    )
    parsed_namespace = urlsplit(namespace)
    if not parsed_namespace.scheme or any(
        character.isspace() for character in namespace
    ):
        raise OperationalError(f"{label} document namespace is not a URI")
    creation = object_value(document.get("creationInfo"), f"{label} creation info")
    creators = creation.get("creators")
    if (
        not isinstance(creators, list)
        or not creators
        or any(
            not isinstance(item, str) or _CREATOR.fullmatch(item) is None
            for item in creators
        )
    ):
        raise OperationalError(f"{label} creators are malformed")
    _created_timestamp(creation.get("created"), label=label)

    identifiers = {"SPDXRef-DOCUMENT"}
    for collection_name in ("packages", "files", "snippets"):
        collection = document.get(collection_name, [])
        if not isinstance(collection, list):
            raise OperationalError(f"{label} {collection_name} must be an array")
        for raw_element in collection:
            element = object_value(raw_element, f"{label} {collection_name} element")
            identifier = string_value(
                element.get("SPDXID"), f"{label} {collection_name} SPDX identifier"
            )
            if _SPDX_IDENTIFIER.fullmatch(identifier) is None:
                raise OperationalError(
                    f"{label} {collection_name} SPDX identifier is malformed"
                )
            if identifier in identifiers:
                raise OperationalError(f"{label} repeats SPDX identifier {identifier}")
            identifiers.add(identifier)
            if collection_name == "packages":
                string_value(element.get("name"), f"{label} package name")
                string_value(
                    element.get("downloadLocation"),
                    f"{label} package download location",
                )
                files_analyzed = element.get("filesAnalyzed")
                if not isinstance(files_analyzed, bool):
                    raise OperationalError(
                        f"{label} package filesAnalyzed must be boolean"
                    )
            elif collection_name == "files":
                string_value(element.get("fileName"), f"{label} file name")

    described = document.get("documentDescribes", [])
    if not isinstance(described, list) or any(
        not isinstance(item, str) or item not in identifiers for item in described
    ):
        raise OperationalError(f"{label} documentDescribes is malformed")
    relationships = document.get("relationships", [])
    if not isinstance(relationships, list):
        raise OperationalError(f"{label} relationships must be an array")
    for raw_relationship in relationships:
        relationship = object_value(raw_relationship, f"{label} relationship")
        for field in ("spdxElementId", "relationshipType", "relatedSpdxElement"):
            string_value(relationship.get(field), f"{label} relationship {field}")
    return document


def _created_timestamp(value: object, *, label: str) -> None:
    text = string_value(value, f"{label} creation time")
    if not text.endswith("Z"):
        raise OperationalError(f"{label} creation time must use UTC")
    try:
        created = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise OperationalError(f"{label} creation time is malformed") from exc
    if created.utcoffset() != UTC.utcoffset(created):
        raise OperationalError(f"{label} creation time must use UTC")
