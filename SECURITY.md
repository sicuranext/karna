# Security Policy

Karna is a Web Application Firewall, so we take security reports seriously and
appreciate responsible disclosure.

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Report privately to **karna@sicuranext.com**. You can also reach the maintainers
on the [SicuraNext Discord](https://discord.gg/FaHMZfmqty) (`#karna`) to coordinate,
but send the vulnerability details by email, not in chat. Ask in your first email
if you want to encrypt the report.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal request, rule config, or payload),
- the Karna version (the `VERSION` in `handler.lua` or the rockspec) and how you run it.

## What to expect

- We aim to acknowledge a report within 3 business days.
- We will work with you on a fix and a coordinated disclosure timeline.
- With your consent, we will credit you in the release notes.

## Scope

In scope: the Karna plugin source in this repository (engine, parsers, schema,
rule controls, body parsers).

Out of scope: vulnerabilities in Kong Gateway, OpenResty, or third-party
dependencies (report those to their own projects), and issues that require a
deployment you misconfigured yourself, such as an exposed Kong Admin API.

## Supported versions

Karna follows SemVer. Security fixes land on the latest released minor version.
