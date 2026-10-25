# Security policy

The observer runs on people's computers and handles agent activity, so we take
reports seriously and appreciate responsible disclosure.

## Reporting a vulnerability

Please do **not** open a public issue or pull request.

Report it privately through
[GitHub private vulnerability reporting](https://github.com/phigonai/observer/security/advisories/new),
or by email to **nikku@phigon.online** with "Security" in the subject. Include
the affected version, the steps to reproduce, and the impact you expect.

We aim to acknowledge reports within three working days, keep you informed
while we fix the problem, and credit you in the release notes unless you prefer
otherwise.

## Supported versions

Security fixes are released for the latest major version of
`@phigon/observer`. Update with:

```sh
phigon-observer update
```

## Scope

In scope: this repository, the `@phigon/observer` npm package and the Guardian
runner binaries it ships. Issues in a Phigon control plane or the Phigon app
can be reported the same way.
