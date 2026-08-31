"""Runtime validation for retained SPDX 2.3 JSON documents."""

import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from conclear.errors import OperationalError

_SPDX_IDENTIFIER = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
_CREATOR = re.compile(r"^(?:Person|Organization|Tool):\s*\S.*$")


def validate_spdx_document(value: object, *, label: str) -> dict[str, object]:
    """Validate mandatory SPDX 2.3 document creation and element identities."""
    document = _object(value, label)
    if document.get("spdxVersion") != "SPDX-2.3":
        raise OperationalError(f"{label} is not an SPDX 2.3 document")
    if document.get("dataLicense") != "CC0-1.0":
        raise OperationalError(f"{label} has an invalid SPDX data license")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise OperationalError(f"{label} has an invalid document SPDX identifier")
    _nonempty(document.get("name"), f"{label} name")
    namespace = _nonempty(
        document.get("documentNamespace"), f"{label} document namespace"
    )
    parsed_namespace = urlsplit(namespace)
    if not parsed_namespace.scheme or any(
        character.isspace() for character in namespace
    ):
        raise OperationalError(f"{label} document namespace is not a URI")
    creation = _object(document.get("creationInfo"), f"{label} creation info")
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
            element = _object(raw_element, f"{label} {collection_name} element")
            identifier = _nonempty(
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
                _nonempty(element.get("name"), f"{label} package name")
                _nonempty(
                    element.get("downloadLocation"),
                    f"{label} package download location",
                )
                files_analyzed = element.get("filesAnalyzed")
                if not isinstance(files_analyzed, bool):
                    raise OperationalError(
                        f"{label} package filesAnalyzed must be boolean"
                    )
            elif collection_name == "files":
                _nonempty(element.get("fileName"), f"{label} file name")

    described = document.get("documentDescribes", [])
    if not isinstance(described, list) or any(
        not isinstance(item, str) or item not in identifiers for item in described
    ):
        raise OperationalError(f"{label} documentDescribes is malformed")
    relationships = document.get("relationships", [])
    if not isinstance(relationships, list):
        raise OperationalError(f"{label} relationships must be an array")
    for raw_relationship in relationships:
        relationship = _object(raw_relationship, f"{label} relationship")
        for field in ("spdxElementId", "relationshipType", "relatedSpdxElement"):
            _nonempty(relationship.get(field), f"{label} relationship {field}")
    return document


def _created_timestamp(value: object, *, label: str) -> None:
    text = _nonempty(value, f"{label} creation time")
    if not text.endswith("Z"):
        raise OperationalError(f"{label} creation time must use UTC")
    try:
        created = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise OperationalError(f"{label} creation time is malformed") from exc
    if created.utcoffset() != UTC.utcoffset(created):
        raise OperationalError(f"{label} creation time must use UTC")


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OperationalError(f"{label} must be an object")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalError(f"{label} must be a non-empty string")
    return value
