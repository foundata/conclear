# Contributing

Thank you for your interest in contributing. This file provides an overview of
the contribution workflow. Summary:

- Use Issues if you want to report a problem or want to see a feature.
- Create a pull request (PR) to submit code.
- Send an email to the maintainer if you have something to discuss (no support
  requests).


## Issues

If you spot a problem, have an idea or a feature request,
[search if an issue already exists](https://github.com/foundata/conclear/issues).
If a related issue doesn't exist, you can simply open a new issue.

As a general rule, we don't assign issues to anyone. If you find an issue to
work on, you are welcome to open a pull request (PR) with a fix or feature. So
if there is an existing issue you are interested in, just work on it. You might
leave a comment there to inform others that there is work going on.


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


## Discussions

There is no public discussion or forum. If you have something to discuss or
comment about the project, feel free to send an email to Andreas Haerter
<ah@foundata.com> (no support requests, all resources are provided "as is").


## Pull Requests (PRs)<a id="pull-requests"></a>

Make sure you read [`DEVELOPMENT.md`](./DEVELOPMENT.md). Make sure:

1. That all source code or other components are compatible with the project's
   [licensing](./README.md#licensing-copyright) and are traceable. Otherwise, we
   cannot accept your contribution.
2. Your code is working / fix the problem / introduce a sane new feature.
   Formatting, linting, strict typing, the generated conformance catalog,
   compatibility inventory, implementation matrix and unit suite must pass, and
   documentation is updated in the same commit as the behavior it describes.
3. Your PR contains a proper commit message with a description of the change and
   reasoning, following the `<scope>: <description>` format. Bonus: reference an
   issue (if any; PRs without a related issue are still welcome).
4. Changes to [`ARCHITECTURE.md`](./ARCHITECTURE.md), `IPnnnn` promises, the
   shipped JSON schemas, record layouts, exit statuses, CLI options or `CCnnnn`
   identifiers are contract changes. Put each one in its own commit whose
   subject says so. Architecture text describes implemented and tested behavior;
   keep planned behavior in a GitHub issue. Do not silently weaken a promise to
   hide an implementation defect: make a deliberate contract correction with its
   rationale, or fix the code.

If you do not know how to open a PR, there is plenty of useful information
around on the web. Github is also providing quite good documentation:

- [Forking a repository](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo#fork-an-example-repository)
  so that you can make your changes without affecting the original project until
  we merge them.
- [Branches](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-branches#working-with-branches)
- [Pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork)
