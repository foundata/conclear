# Contributing

Changes must preserve the normative OCI guide contract in [DESIGN.md](DESIGN.md), the public CLI and JSON interfaces, stable exit statuses, shipped schemas, record formats and `CCnnnn` identifiers.

## Changes

Keep each change focused and include its tests, schema changes, generated conformance output and affected documentation. Avoid unrelated refactoring and dependency additions. New external dependencies need a concrete requirement that the standard library or an existing dependency cannot meet.

Treat configuration, JSON, registry responses, OCI layouts, archives, paths and tool output as untrusted input. Validate them at runtime before constructing typed domain values.

Exercise failure, interruption, resume and cleanup behavior when a change touches state or an external mutation. Registry writes, signing and network tests require an explicitly authorized disposable environment.

Run the checks in [DEVELOPMENT.md](DEVELOPMENT.md) before committing. Run the full clean-checkout release check when the change affects packaging, supported Python versions, the CLI entry point or distribution contents.

## Design changes

[DESIGN.md](DESIGN.md) is the behavioral contract, not a description of the current code. Put every DESIGN.md edit in its own commit whose subject names it as a contract change, such as `design: require a new run after an ambiguous candidate write`, and never fold one into a commit that also changes code. Give the reason in the commit body when the diff does not carry it.

Do not amend the contract to match an implementation that turned out differently. When the code cannot meet a documented rule, leave the rule alone and report the conflict so the owner decides whether the design or the code changes.

Report every contract change when reporting completed work. A summary that lists implemented behavior but omits an edit to DESIGN.md, a shipped schema, an exit status, a record layout or a `CCnnnn` identifier is incomplete.

## Compatibility

ConClear follows Semantic Versioning. The Click hierarchy, command options, `--format json` objects, JSON Schemas, record layouts, exit statuses and stable check identifiers are compatibility surfaces. Change them deliberately and document the effect.

Do not add a changelog before the project reaches 1.0.0. Do not prepare releases, create tags or push from local validation work.

## Commits

Use `<scope>: <description>` with an imperative lowercase description, normally no longer than 72 characters. Keep logical changes in separate commits and include a body only when the reasoning cannot be recovered from the diff.

Do not use a bare `docs` scope; name the affected subsystem or use a stable cross-cutting scope.
