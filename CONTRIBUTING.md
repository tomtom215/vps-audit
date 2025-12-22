# Contributing to VPS Audit

Thank you for your interest in contributing to VPS Audit! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature or fix

## Development Setup

### Prerequisites

- Bash 4.0+
- ShellCheck (for linting)
- Docker (for running the test matrix)

### Installing ShellCheck

```bash
# Debian/Ubuntu
sudo apt-get install shellcheck

# macOS
brew install shellcheck

# Fedora
sudo dnf install ShellCheck
```

### Running Tests

```bash
# Run integration tests
./tests/integration-tests.sh

# Run tests on a specific distribution (requires Docker)
./test-matrix.sh ubuntu:24.04

# Run full test matrix (requires Docker)
./test-matrix.sh
```

### Running ShellCheck

```bash
# Check all scripts (uses .shellcheckrc for configuration)
shellcheck vps-audit.sh test-matrix.sh tests/integration-tests.sh
```

## Code Style

- Use 4-space indentation (no tabs)
- Follow existing code patterns and conventions
- Add comments for complex logic
- Use meaningful variable and function names

### Shell Script Guidelines

- Use `#!/usr/bin/env bash` shebang
- Quote variables to prevent word splitting: `"$variable"`
- Use `[[ ]]` for conditionals (Bash-specific)
- Use `$(command)` instead of backticks
- Check command existence with `command -v` or `has_command()`

## Pull Request Process

1. **Ensure tests pass**: Run the integration tests before submitting
2. **Run ShellCheck**: Ensure no new warnings are introduced
3. **Update documentation**: Update README.md if adding new features
4. **Write clear commit messages**: Use conventional commit format when possible

### Commit Message Format

```
type: short description

Longer description if needed.
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `ci`: CI/CD changes
- `refactor`: Code refactoring
- `test`: Test additions or changes

## Reporting Issues

When reporting issues, please include:

1. Operating system and version
2. Bash version (`bash --version`)
3. Full error output
4. Steps to reproduce

## Adding New Security Checks

When adding a new security check:

1. Add the check function following the naming pattern: `check_<category>_<name>()`
2. Use `should_run_check "<category>"` at the start of the function
3. Use the `check_security` function for consistent output formatting
4. Add the check to the `main()` function
5. Update the help text and README with the new check category
6. Add integration tests for the new check

### Example Check Structure

```bash
check_example_feature() {
    should_run_check "example" || return 0

    # Perform the check
    local result
    result=$(some_command 2>/dev/null)

    if [[ "$result" == "expected" ]]; then
        check_security "Example Feature" "PASS" "Feature is configured correctly" ""
    else
        check_security "Example Feature" "WARN" "Feature needs attention" \
            "Recommendation for fixing the issue"
    fi
}
```

## Questions?

If you have questions about contributing, please open an issue for discussion.
