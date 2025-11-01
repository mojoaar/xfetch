# Contributing to xfetch

Thanks for your interest in contributing to xfetch! Contributions are welcome — bug reports, small fixes, tests, or feature proposals are all helpful.

How to contribute

1. Fork the repository and create a feature branch: `git checkout -b my-fix`
2. Run `go fmt ./...` and `go test ./...` and ensure tests pass.
3. Open a pull request with a clear description of the change.

Guidelines

- Keep Windows-specific code in files with the `//go:build windows` build tag.
- Write small, focused commits and include tests for new behavior when possible.
- Use the existing logging/debug pattern (set `XFETCH_DEBUG=1`) when adding diagnosable behavior.

License

By contributing, you agree that the contribution will be under the project's MIT license.
