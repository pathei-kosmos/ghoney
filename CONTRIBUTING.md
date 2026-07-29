# Contributing to ghoney

Bug reports and focused improvements are welcome. Please open an issue before proposing a substantial feature: ghoney deliberately favors a small, auditable surface over configurability.

## Pull requests

1. Fork the repository and create a focused branch.
2. Keep changes compact, dependency-light, and explicit about security tradeoffs.
3. Comment non-obvious code and tests with the reason behind the behavior.
4. Run the local checks:

   ```bash
   go fmt ./...
   go test ./...
   go vet ./...
   docker build -t ghoney .
   ```

5. Include targeted tests for behavior changes. Avoid redundant assertions based on response wording or implementation details.
6. Submit a pull request describing the problem, the chosen tradeoff, and how it was verified.

Changes to `seccomp.json`, container isolation, request parsing, logging, or dashboard rendering must include a regression test or an integration check.
