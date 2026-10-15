## What and why

## Checklist
- [ ] `make test` passes (vet, race tests, end-to-end hook tests)
- [ ] New or changed rules have a generated sample in `internal/detect/detect_test.go` (no real or realistic literal secrets in the repo)
- [ ] Detection changes: ran `python3 bench/run.py` and noted recall/noise before vs after
- [ ] Docs updated (README / docs/using-secrets.md) if behaviour changed
