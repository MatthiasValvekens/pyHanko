# Contributing to pyHanko

Hi, thanks for checking in! As I write this, pyHanko has been on GitHub for
about a year and a half, and the codebase has grown a lot. Since there has been
some discussion in issues and pull requests over the course of the past few
months or so, I figured now would be a good time to set forth some contribution
guidelines.


## Code of conduct

Interactions between contributors are governed by the
[Code of Conduct](CODE_OF_CONDUCT.md),
which is based on the standard Contributor Covenant template. Discussion is
allowed and encouraged, but be civil, play nice, share your toys; the usual.


## Use of the issue tracker and discussion forum

### Questions about pyHanko

**Please do not ask for support on the issue tracker.** The issue tracker is for bug
reports and actionable feature requests. Questions related to pyHanko usage
and development should be asked in the discussion forum instead.

Note that community support is provided on a best-effort basis without any
service level guarantees.


### Bug reports

If you think you've encountered a bug in pyHanko, you can submit a bug report
in the issue tracker by filling out the bug report template. Please include all
relevant information indicated in the template.

Some additional pointers:

 * For bugs in library code, always include a stack trace, and (if at all
   possible) a minimal, reproducible code sample.
 * For issues with CLI bugs, include the full output in `--verbose` mode.
 * When available, example files are appreciated. If you're not comfortable
   sharing your example files in public, you can also email them to
   `pyhanko.samples@mvalvekens.be`.

**IMPORTANT: NEVER disclose production private keys in your bug reports or
in your e-mails.**


### New features

If you have an idea for a feature, consider allowing for some discussion on
the discussion forum before creating a feature request in the issue tracker
or submitting a PR. This allows for smoother collaboration, ensures that
feature requests stay within the project's scope, and increases the chances
that your feature request or PR will be worked on and/or reviewed.

If you need ideas, take a look at [currently open feature requests][feature-requests],
or ask on the discussion forum.

[feature-requests]: https://github.com/MatthiasValvekens/pyHanko/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement


## Compatibility


### General policy

Currently, pyHanko aims to remain compatible with Python versions 3.7 and up,
and this is expected of new contributions as well (for the time being).

PyHanko follows [SemVer](https://semver.org/), but has not yet reached `1.0.0`.
**As such, breaking changes in the public API may still occur.**


Unlike some other projects, pyHanko's philosophy distinguishes the public and
internal elements of its API through the documentation, rather than through
any particular language features. For compatibility purposes, the public API
is defined as follows:

 1. A module is public by default if its name does not start with an underscore,
    unless otherwise specified in the module documentation.
 2. Documented members (classes, functions and constants) of public modules
    listed in `__all__` are considered public API, unless the documentation
    says otherwise. The same applies to members of classes that qualify as
    public.
 3. In public classes, exact method signatures that are designed to be
    overridden (indicated by a `raise NotImplementedError` or by documentation)
    are also considered part of the public API.


Everything else is considered internal API and subject to change without notice,
even after pyHanko reaches version `1.0.0`. In particular, the following
are specifically _not_ covered by any API guarantees:

 - Non-public modules and their members.
 - _All_ undocumented functionality.
 - If the documentation says something is internal, then it is.
 - Signatures of public methods on classes, unless covered under item 3 of
   the previous paragraph.

The last point should be interpreted carefully: public methods will never
stop accepting certain parameters without a major version bump, but
may _gain_ additional optional parameters, unless the method is designed to be
overridden in subclasses. In other words, the default position is to honour
API compatibility for _calling_ code only, not for _extending_ code.
Exceptions to this rule are documented explicitly.


Any relaxation of this compatibility policy (after `1.0.0`) is also cause for
a major version bump.


### For contributors

While breaking changes between releases are still permitted, they must be
well-documented and motivated. Documentation for such changes must be supplied
in a format suitable for inclusion in the release notes.

Changes in internal APIs and new code (this includes all code that is not yet
part of any release tag) are fair game, but PRs proposing such changes must
include a summary describing what breaks in which way.

Dependency changes (both version changes and new dependencies) must always be
motivated. Besides issues of technical compatibility, also consider the
licence under which said dependencies are made available.


## Tests

As a general rule, all PRs should have 100% statement coverage on new code.
Deviations are permitted but must be motivated.

In addition, keep in mind the following when writing test cases:

 * Test both the "happy path" (i.e. expected input) and error behaviour.
 * Make liberal use of [Certomancer][certomancer] for PKI
   service mocking. If you need help, just ask on the discussion forum, or in
   your PR.
 * When committing a bugfix, verify that your new tests fail before the fix
   was applied.
 * Don't just shoot for high statement coverage. Diversity in scenarios is
   hard to measure, but no less important.

[certomancer]: https://github.com/MatthiasValvekens/certomancer

## Code style

Code style is currently not formally standardised; fixing that is on the TODO
list. As such, code style issues will be handled on a case-by-case basis for
the time being (sorry about that).

Nevertheless, here are some pointers.

 * Avoid overly long function definitions.
 * Avoid letting builtin exceptions (`KeyError`, `ValueError`, ...) bubble up
   through public API entry points.
 * Docstrings must be written in ReStructured Text.
 * All new public API entry points must be documented. Documentation may be
   omitted from internal API functions if their purpose is sufficiently clear.
 * As a general rule, keep your lines under 80 characters. This makes it easier
   to view multiple files side-by-side on a single monitor. Exceeding the limit
   is permissible in documentation files.
 * Format imports using `isort --profile black --line-length 80`.
 * Check for whitespace errors using `git diff-index --check --cached HEAD`.

You can put the last two in a pre-commit hook to avoid getting yelled at by the
CI linter.


## Copyright issues

PyHanko is distributed under the [MIT licence](LICENSE), and explicitly does
*not* require its contributors to sign a contributor licence agreement (CLA).
Our approach is instead based on the
[Developer certificate of origin (DCO)][dco], reproduced below.

[dco]: https://developercertificate.org/

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.

```

In particular, the DCO allows you to retain ownership of your changes,
while permitting them to be distributed under the terms of the project's
licence.
