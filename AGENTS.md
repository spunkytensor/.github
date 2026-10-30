# Shared security automation

- Support both public and private repositories with the same baseline.
- Allow GitHub Actions.
- Keep paid private-repository security add-ons optional.
  These add-ons include GitHub Code Security/Advanced Security, hosted CodeQL, and dependency-review services.
- Keep security scripts standalone.
- Make scripts run locally without GitHub security settings or tokens.
- Use Actions to call scripts that own the security logic.
- Document possible charges for private-repository Actions minutes and artifact storage.
- Preserve fail-closed High/Critical gates.
- Preserve immutable pins.
- Preserve evidence on failure.
- Document coverage gaps.
- Keep private repository names, reports, SBOMs, and findings out of this public repository's logs and artifacts.
- Run private monitoring on a private host.
- Run `python -m unittest discover -s tests -v` for validation.
- Run actionlint for validation.
- Run a live Trivy scan after changes to scanner integration.

## Documentation style

Write in ASD-STE100 Simplified Technical English, Issue 9.
Apply these rules to editable documentation prose.
Preserve license texts, copyright notices, and required attribution verbatim.

- Put one instruction in each sentence.
- Limit procedural sentences to 20 words.
- Limit descriptive sentences to 25 words.
- Use the imperative mood for procedures.
- Use active voice throughout.
- Use simple tenses only.
- Avoid perfect and progressive tenses.
- Avoid gerunds as verbs.
- Use each word with one meaning.
- Use the same term for the same reference throughout.
- Avoid synonym rotation.
- Describe only what exists now.
- Omit historical narratives.
- Omit negative examples.
