# Development

Run commands from the repository root.

## Amp orbs

`.agents/setup` installs Python 3.12, `requirements.txt` dependencies, actionlint 1.7.12, and Trivy 0.76.1.
It verifies tool checksums and reuses installed dependencies.
It stores the environment at `~/.cache/amp/spunkytensor-baseline`, outside source scans.
New login shells in this checkout use that environment automatically.
Run `.agents/setup` after requirements change.

`.agents/resume` checks tool availability without network access or installation.
Setup requires no services, tokens, or authentication.
Setup requires internet access and Amp's x64 Debian orb template with preinstalled `uv`.

## Local checks

For environments outside Amp orbs:

1. Create a Python 3.12 virtual environment.
2. Activate the environment.
3. Install [actionlint 1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12) from its official release.

Run these checks in either environment:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m bandit -r scripts -lll
actionlint .github/workflows/*.yml
```

Keep actions and tools pinned.
Tests cover scan success and failure.
Run a live Trivy scan after changes to scanner integration.
Original material uses Apache-2.0.
See [LICENSE](../LICENSE) and [third-party notices](../THIRD_PARTY_NOTICES.txt).
