# Security Policy


## Supported Versions

As this project has not yet reached `1.0.0`, all releases are considered
mutually incompatible by default under [SemVer](https://semver.org/).
Moreover, all releases other than the latest one are considered obsolete.

While the project is in this stage, security fixes will only be applied to the
latest `0.x.y` release. If the fix does not necessitate breaking changes or
major dependency upgrades, `y` will be incremented. If more work is necessary,
`x` will be incremented prior to re-releasing.


## Reporting a Vulnerability

Please don't hesitate to email me if you think you've found a security
vulnerability in pyHanko or one of its dependencies.

Depending on your preferences, you can either contact me at `dev@mvalvekens.be`,
or use the contact information and PGP key that are listed
[on my website][website]. I'll do my best to get back to you within 24 hours
to assess the scope of the issue. We can discuss severity, possible fixes,
mitigations and disclosure timelines over email. In the meantime, standard
responsible disclosure practices apply.

Proof-of-concept code and/or sample documents are appreciated if available.


[website]: https://mvalvekens.be/contact.html


## Spec issues

Note that code analysis tools may report various issues regarding the use of
weak or outdated cryptographic algorithms, in particular in the code that
handles file encryption and decryption. Usually, these relate to historical
baggage in the PDF standard, and therefore they can't be addressed within
pyHanko without breaking compatibility with other PDF tooling.

Keep that in mind, but when in doubt, report the issue anyway. Better safe than
sorry.
