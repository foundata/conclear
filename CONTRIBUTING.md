# Contributing

Changes must preserve the normative OCI guide contract in [DESIGN.md](DESIGN.md), the public CLI and JSON interfaces, stable exit statuses, shipped schemas, record formats and `CCnnnn` identifiers.

## Changes

Keep each change focused and include its tests, schema changes, generated conformance output and affected documentation. Avoid unrelated refactoring and dependency additions. New external dependencies need a concrete requirement that the standard library or an existing dependency cannot meet.

Treat configuration, JSON, registry responses, OCI layouts, archives, paths and tool output as untrusted input. Validate them at runtime before constructing typed domain values.

Exercise failure, interruption, resume and cleanup behavior when a change touches state or an external mutation. Registry writes, signing and network tests require an explicitly authorized disposable environment.

Run the checks in [DEVELOPMENT.md](DEVELOPMENT.md) before committing. Run the full clean-checkout release check when the change affects packaging, supported Python versions, the CLI entry point or distribution contents.

## Compatibility

ConClear follows Semantic Versioning. The Click hierarchy, command options, `--format json` objects, JSON Schemas, record layouts, exit statuses and stable check identifiers are compatibility surfaces. Change them deliberately and document the effect.

Do not add a changelog before the project reaches 1.0.0. Do not prepare releases, create tags or push from local validation work.

## Commits

Use `<scope>: <description>` with an imperative lowercase description, normally no longer than 72 characters. Keep logical changes in separate commits and include a body only when the reasoning cannot be recovered from the diff.

Do not use a bare `docs` scope; name the affected subsystem or use a stable cross-cutting scope.
