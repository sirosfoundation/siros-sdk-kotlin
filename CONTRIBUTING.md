# Contributing to SIROS SDK for Android (Kotlin)

Thank you for your interest in contributing to the SIROS SDK.

## Development Setup

1. Clone the repository
2. Open in Android Studio (Iguana or later)
3. Sync Gradle and build: `./gradlew build`
4. Run tests: `./gradlew test`

## Code Style

- Follow [Kotlin coding conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Use `internal` visibility by default; only expose `public` API intentionally
- All public API must have KDoc documentation
- All exceptions must extend `SirosException`

## Testing

- All new code must include unit tests
- Coverage gate: **25% minimum** (enforced in CI, target 70%+)
- Use MockWebServer for HTTP tests, fake transports for WMP tests
- No tests that depend on external/shared environments

## Pull Requests

1. Create a feature branch from `main`
2. Keep commits focused and well-described
3. Ensure CI passes (build + test + coverage gate)
4. Request review from a maintainer

## Security

If you discover a security vulnerability, please report it privately to security@siros.org.
Do **not** open a public issue for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the BSD 2-Clause License.
