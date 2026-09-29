# Shared security automation

- Support both public and private repositories with the same baseline.
- GitHub Actions is allowed. Do not require optional GitHub services or security
  add-ons that cost money for private repositories, including GitHub Code
  Security/Advanced Security, hosted CodeQL, or dependency-review services.
- Keep security scripts standalone and runnable locally without GitHub security
  settings or tokens. Actions should wrap those scripts, not own their logic.
- Ordinary private-repository Actions minutes and artifact storage may incur
  usage charges; do not describe Actions as unlimited or universally free.
- Preserve fail-closed High/Critical gates, immutable pins, and evidence on failure.
  Document coverage gaps rather than silently disabling checks.
- Never publish private repository names, reports, SBOMs, or findings in this
  public repository's logs or artifacts. Run private monitoring in a private host.
- Validate with `python -m unittest discover -s tests -v`, actionlint, and a live
  Trivy scan when changing scanner integration.
