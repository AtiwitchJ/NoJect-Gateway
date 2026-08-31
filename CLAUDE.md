# CLAUDE.md - NoJect Agent Guidance

Please refer to [AGENTS.md](AGENTS.md) for full context, architecture details, and roadmap.

## Quick Cheat Sheet

### Verification & Testing
- Run all tests: `make test`
- Run all benchmarks: `make bench`
- Build all packages: `make all`

### Python Library (with Astral uv)
- Test: `cd packages/noject-python && uv run pytest tests/ -v`
- Build: `cd packages/noject-python && uv build`

### TypeScript Library (npm)
- Test: `cd packages/noject-ts && npm test`
- Build: `cd packages/noject-ts && npm run build`

### Go Core Gateway
- Test: `go test -v ./...`
- Build: `go build -o bin/noject-gateway cmd/gateway/main.go`

### Important Rules
- Maintain 100% test passing score on all 90 attack vectors.
- Strict ISO wording: "Architected in Alignment with ISO/IEC 27001:2022 & ISO/IEC 42001:2023 Principles".
- Keep fast-path latency under 0.001 ms (1 µs).
