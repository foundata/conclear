# Contributing

Thank you for your interest in contributing. Use these channels:

- Open an issue to report a problem or request a feature.
- Submit code through a pull request (PR) or merge request (MR).
- Send an email to the maintainer if you have something to discuss (no support
  requests).

Development takes place on our internal repository hosting platform. You can
report issues and submit changes through any of our public repositories on
platforms such as GitHub, GitLab or Codeberg. We coordinate the work internally
and follow up on the platform where you contributed.

> **Important:** ConClear is built for foundata's release process. You are
> welcome to use it if you adopt the requirements of
> [foundata's OCI container image build and release guide](https://foundata.com/en/guidelines/oci-images/),
> but submissions to adapt ConClear to different release policies are out of
> scope.

Report security vulnerabilities privately as described in
[`SECURITY.md`](./SECURITY.md).


## Issues<a id="issues"></a>

If you spot a problem, have an idea or want to request a feature, use the issue
tracker where this project's repository is hosted, such as GitHub, GitLab or
Codeberg. Search the existing issues there before opening a new one.

You only need to report an issue once, on one platform. If you know of a related
issue on another platform, include its full URL so we can connect the reports.

We don't assign issues automatically. Leave a comment if you'd like to work on
an issue or have already started. You can also ask us to assign it to you.


### Report a release or check problem<a id="issues-release-problems"></a>

ConClear fails closed, so a report is only actionable when it distinguishes a
rule rejection (exit status `2`, the image or repository violates a documented
requirement) from an operational failure (exit status `1`, a fact could not be
established). Include:

1. `conclear version --format json`, which identifies both the tool revision and
   the exact guide revision it implements.
2. The failing command and its exit status.
3. The `--format json` result object. It names the `CCnnnn` identifier for a
   rule rejection and classifies an operational failure, and it never contains
   secret values.
4. The relevant part of `conclear.toml`, with registry names left intact.

Review the attachment before sending: run workspaces contain local filesystem
paths, and evidence records name registries and digests. ConClear redacts
credentials, authorization headers, passphrases and secret mount paths from logs
and errors, but it cannot redact a path you paste by hand.

When a check identifier is wrong rather than merely unwelcome, say which guide
requirement you expected it to enforce. The
[conformance catalog](./docs/conformance.md) maps every identifier to a guide
anchor, so a mismatch between the two is itself a defect worth reporting.


## Discussions<a id="discussions"></a>

There is no public discussion or forum. If you have something to discuss or
comment about the project, feel free to send an email to Andreas Haerter
<ah@foundata.com> (no support requests, all resources are provided "as is").


## Submitting changes<a id="submitting-changes"></a>

Read [`DEVELOPMENT.md`](./DEVELOPMENT.md).

The following requirements apply to both pull requests and merge requests:

1. That all source code or other components are compatible with the project's
   [licensing](./REUSE.toml) and are traceable. Otherwise, we cannot accept your
   contribution.
2. Your code works and fixes the problem or implements the proposed feature.
   Formatting, linting, strict typing, the generated conformance catalog,
   compatibility inventory, implementation matrix and unit suite must pass, and
   documentation is updated in the same commit as the behavior it describes.
3. Your submission contains a proper commit message with a description of the
   change and reasoning, following the `<scope>: <description>` format. You may
   reference a related issue; submissions without a related issue are also
   welcome.
4. Changes to [`ARCHITECTURE.md`](./ARCHITECTURE.md), `IPnnnn` promises, the
   shipped JSON schemas, record layouts, exit statuses, CLI options or `CCnnnn`
   identifiers are contract changes. Put each one in its own commit whose
   subject says so. Architecture text describes implemented and tested behavior;
   keep planned behavior in an issue. Do not silently weaken a promise to
   hide an implementation defect: make a deliberate contract correction with its
   rationale, or fix the code.

Working on a branch in your own fork lets you make changes without affecting the
original project until we merge them. For help with forks, branches and
submitting changes, use the documentation for the platform hosting the
repository:

| Platform |  Submission type   | Help |
| -------- | ------------------ | ---- |
| GitHub   | Pull request (PR)  | [Quickstart for pull requests](https://docs.github.com/en/pull-requests/get-started/pull-request-quickstart) |
| GitLab   | Merge request (MR) | [Create merge requests](https://docs.gitlab.com/user/project/merge_requests/creating_merge_requests/) |
| Forgejo  | Pull request (PR)  | [Pull requests and Git flow](https://forgejo.org/docs/latest/user/collaboration/pull-requests-and-git-flow/) |
