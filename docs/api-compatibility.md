# API Compatibility Policy

`advent-prompt-pwn` follows Semantic Versioning beginning with version 1.0.0.

## Public interfaces

The following are public and covered by compatibility guarantees within a major version:

- Names exported from `advent_prompt_pwn.__all__`
- The `Target`, `Strategy`, and `Oracle` extension interfaces
- Version 1 corpus, engagement-manifest, and minimal-reproducer fields
- Version 1 JSON report, minimal-reproducer, and evidence-bundle schemas
- Documented CLI commands, options, and exit-code meanings
- The `advent_prompt_pwn.strategies` plugin entry-point group

Adding an optional field, enum value, strategy, oracle, target, report format, or CLI option is backward compatible. Removing or renaming a public name, changing a required argument, changing success semantics, or rejecting a previously valid versioned document requires a new major version unless the old behavior is a documented security vulnerability.

## Deprecation

Deprecated Python and CLI interfaces remain available for at least one minor release and emit a migration notice before removal. Security-sensitive behavior may be disabled sooner when preserving it would expose users to material risk. Release notes will describe the reason and migration path.

## Schemas

Corpus, engagement, report, and bundle versions are independent of the package version. Readers reject unsupported major schema versions. New optional fields may be added to an existing schema version when older readers can safely ignore them.

## Non-guaranteed behavior

Private names beginning with an underscore, generated prose, timestamps, run IDs, target-model behavior, provider-specific metadata, plugin internals, and undocumented implementation details are not compatibility commitments.

Python versions are supported as listed in package metadata and `SECURITY.md`. A Python version can be removed in a major release or after its upstream security support ends, with advance notice when practical.
