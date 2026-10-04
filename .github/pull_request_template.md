## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## How it was verified

<!-- Commands you ran and what they showed. For a check: the state you created and the verdict it gave. -->

## Checklist

- [ ] Tests added or updated (`./tests/run.sh` passes, as root and as a normal user)
- [ ] `shellcheck -x` and `shfmt -d` are clean (see CONTRIBUTING.md)
- [ ] A bug fix has a regression test that fails without the fix
- [ ] README / `--help` / CHANGELOG.md updated if behaviour or options changed
- [ ] The check stays read-only and degrades gracefully when a tool is missing
