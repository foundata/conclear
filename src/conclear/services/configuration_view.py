"""A read-only summary of resolved policy values and their origins."""

import json
import tomllib
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from conclear.config import (
    MAX_CANDIDATE_LIFETIME,
    MAX_PIN_DIVERGENCE,
    MAX_PIN_FRESHNESS,
    MAX_REMEDIATION,
    SYSTEMD_WRITABLE_MOUNTS,
    ImageConfig,
    ReleaseImageConfig,
    RepositoryConfig,
)
from conclear.config_decisions import RESOURCE_DECISIONS
from conclear.jsonutil import sha256_bytes
from conclear.parsing import toml_table
from conclear.presentation import CommandResult, ResultStatus
from conclear.release_profile import ReleaseProfile


@dataclass(frozen=True, slots=True)
class EffectiveValue:
    """One resolved value with its origin and any decision or policy explanation."""

    value: object
    origin: str
    reason: str
    maximum: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the public explanation without internal configuration objects."""
        return {
            "value": self.value,
            "origin": self.origin,
            "reason": self.reason,
            "maximum": self.maximum,
        }


def configuration_view(
    repository: RepositoryConfig,
    *,
    image_id: str | None,
    version: str | None,
    profile: ReleaseProfile | None,
) -> CommandResult:
    """Summarize validated values without resolving tools or contacting services."""
    source = tomllib.loads(repository.raw_bytes.decode("utf-8"))
    declarations = {item["id"]: item for item in source["images"]}
    images = repository.images if image_id is None else (repository.image(image_id),)
    details: list[str] = []
    rendered: list[dict[str, object]] = []
    for image in images:
        fields = _image_values(
            repository, image, toml_table(declarations[image.image_id]), version
        )
        rendered.append(
            {
                "id": image.image_id,
                "releasable": image.releasable,
                "values": {key: item.to_dict() for key, item in fields.items()},
            }
        )
        details.append(
            f"Image {image.image_id} ({'release' if image.releasable else 'test-only'})"
        )
        for key, item in fields.items():
            details.append(
                f"{key} = {json.dumps(item.value, ensure_ascii=True)} [{item.origin}]"
                + (f"; {item.reason}" if item.reason else "")
                + (f" Maximum {item.maximum}." if item.maximum else "")
            )
    protected = (
        None
        if profile is None
        else {
            "name": profile.name,
            "builderId": profile.builder.id,
            "registryHost": profile.registry.host,
            "publicKeyDigest": profile.public_key_digest,
        }
    )
    if profile is not None:
        details.append(
            f"Protected release profile {profile.name}: builder {profile.builder.id}; registry {profile.registry.host}"
        )
    return CommandResult(
        "config show",
        ResultStatus.SUCCESS,
        "Effective configuration (not a qualification)",
        data={
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "images": rendered,
            "releaseProfile": protected,
        },
        details=tuple(details),
    )


def _image_values(
    repository: RepositoryConfig,
    image: ImageConfig,
    declared: dict[str, Any],
    version: str | None,
) -> dict[str, EffectiveValue]:
    fields: dict[str, EffectiveValue] = {}

    def add(
        name: str,
        value: object,
        reason: str = "",
        *,
        origin: str | None = None,
        maximum: timedelta | None = None,
    ) -> None:
        observed: object = declared
        for part in name.split("."):
            observed = observed.get(part) if isinstance(observed, dict) else None
        fields[name] = EffectiveValue(
            value,
            origin or ("repository" if observed is not None else "default"),
            reason,
            None if maximum is None else _duration(maximum),
        )

    add(
        "containerfile",
        image.containerfile.relative_to(repository.path.parent).as_posix(),
    )
    add("context", image.context.relative_to(repository.path.parent).as_posix())
    add(
        "platforms",
        [str(item) for item in image.platforms],
        "Explicit published coverage; never inferred from the host."
        if image.releasable
        else "Explicit test-dependency build platforms; never inferred from the host.",
    )
    add("test.dependencies", list(image.test_dependencies))
    add(
        "pins",
        [
            {"reference": str(pin.reference), "tag_intent": pin.tag_intent.value}
            for pin in image.pins
        ],
        "Digests come from the Containerfile; tag intent requires owner review.",
        origin="Containerfile + repository intent",
    )
    add(
        "limits.pin_freshness",
        _duration(image.pin_limits.pin_freshness),
        maximum=MAX_PIN_FRESHNESS,
    )
    add(
        "limits.pin_divergence",
        _duration(image.pin_limits.pin_divergence),
        maximum=MAX_PIN_DIVERGENCE,
    )
    runtime = image.runtime
    add(
        "runtime.profile",
        runtime.profile,
        "Choose the lifecycle the runtime tests must exercise.",
    )
    add(
        "runtime.user",
        runtime.user,
        "Must agree with the final numeric USER instruction.",
    )
    for key, reason in RESOURCE_DECISIONS.items():
        add(f"runtime.{key}", getattr(runtime, key), reason)
    mounts = list(SYSTEMD_WRITABLE_MOUNTS) if runtime.profile == "systemd" else []
    add("runtime.profile_mounts", mounts, origin="runtime profile")
    add(
        "runtime.writable_mounts",
        list(runtime.writable_mounts),
        "Includes runtime-profile mounts.",
        origin="repository + runtime profile" if mounts else None,
    )
    add(
        "runtime.read_only",
        runtime.read_only,
        origin="reviewed permission" if not runtime.read_only else "fixed policy",
    )
    add(
        "runtime.no_new_privileges",
        runtime.no_new_privileges,
        origin="reviewed sudo mode"
        if not runtime.no_new_privileges
        else "fixed policy",
    )
    add("runtime.capabilities", list(runtime.capabilities))
    add("runtime.health_command", list(runtime.health_command))
    add("runtime.immutable_paths", list(runtime.immutable_paths))
    add("runtime.startup_timeout_seconds", runtime.startup_timeout_seconds)
    add("runtime.shutdown_timeout_seconds", runtime.shutdown_timeout_seconds)
    for key in ("root_requirement", "writable_root_requirement"):
        requirement = getattr(runtime, key)
        if requirement is not None:
            add(
                f"runtime.{key}",
                requirement.to_dict(),
                "Owner-reviewed permission; it does not waive other controls.",
            )
    if runtime.sudo_requirement is not None:
        sudo = runtime.sudo_requirement
        add(
            "runtime.sudo_requirement",
            {
                **sudo.review.to_dict(),
                "mode": sudo.mode,
                "scope": sudo.scope,
                "setidPaths": list(sudo.setid_paths),
            },
            "Escalation needs an allowed and a denied caller test.",
        )
    if runtime.systemd is not None:
        add(
            "runtime.systemd.required_units",
            list(runtime.systemd.required_units),
            "Explicit units whose readiness must be tested.",
        )
    if runtime.setid_requirements:
        add(
            "runtime.setid_requirements",
            [
                {"path": item.path, **item.review.to_dict()}
                for item in runtime.setid_requirements
            ],
            "Each retained set-ID executable needs its own review.",
        )
    if isinstance(image, ReleaseImageConfig):
        add("repository", image.repository.repository_name)
        add("scanner", "trivy", origin="fixed policy")
        add(
            "native_test_platforms", [str(item) for item in image.native_test_platforms]
        )
        add("rescan_scope", image.rescan_scope)
        add(
            "release.immutable_tags",
            list(image.release.immutable_tags),
            "Requires --version."
            if any("{version}" in tag for tag in image.release.immutable_tags)
            else "",
        )
        add("release.moving_tags", list(image.release.moving_tags))
        if version is not None:
            add(
                "release.rendered_immutable_tags",
                list(image.release.render_immutable(version)),
                origin="rendered",
            )
        add(
            "limits.candidate_lifetime",
            _duration(image.release_limits.candidate_lifetime),
            maximum=MAX_CANDIDATE_LIFETIME,
        )
        add(
            "limits.remediation",
            _duration(image.release_limits.remediation),
            maximum=MAX_REMEDIATION,
        )
    return fields


def _duration(value: timedelta) -> str:
    return f"{int(value.total_seconds() // 3600)}h"
