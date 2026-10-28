# Contributing to DevGuard AI

Thanks for helping improve DevGuard AI!

## Good first contributions
- Add tests for the heuristic checks.
- Improve secret redaction patterns without printing secret values.
- Improve error messages for unavailable Ollama models.
- Add language-specific static analysis integrations.
- Improve keyboard navigation and accessibility.
- Add sample projects for testing.

## Before opening a pull request
1. Create a focused branch.
2. Run `python -m unittest discover -s tests -v`.
3. Explain the problem and the behavior change.
4. Never include credentials, private keys, `.env` files, or private source code in examples.
5. Do not claim a heuristic detects every vulnerability.

## Reporting security concerns
Please avoid posting real secrets or sensitive source code in public issues. Report the affected component and a safe reproduction instead.
