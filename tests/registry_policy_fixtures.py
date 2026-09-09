"""Explicit registry-policy choices shared by release test fixtures."""

from conclear.registry_policy import (
    CandidateCleanupMode,
    CandidateCleanupPolicy,
    RegistryPolicy,
    TagProtectionMode,
    TagProtectionPolicy,
)

STRICT_POLICY = RegistryPolicy(
    TagProtectionPolicy(TagProtectionMode.REQUIRED),
    CandidateCleanupPolicy(
        CandidateCleanupMode.AUTO_PRUNE,
        "test operator",
        "Review abandoned candidates.",
    ),
)

REGISTRY_POLICY_TOML = """tag_protection = {mode = "required"}
candidate_cleanup = {mode = "auto-prune", owner = "test operator", procedure = "Review abandoned candidates."}
"""
