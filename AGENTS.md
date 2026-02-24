# AGENTS.md

## Cursor Cloud specific instructions

This is a **Go plugin** for [Tailpipe](https://tailpipe.io) that collects and queries GCP logs via SQL. It is a single Go module (not a monorepo).

### Key commands

| Task | Command |
|---|---|
| Build & install plugin locally | `make install` |
| Run tests | `go test ./...` |
| Lint | `golangci-lint run --timeout 5m ./...` |
| Print plugin metadata | `go build -tags netgo -o tailpipe-plugin-gcp.plugin *.go && ./tailpipe-plugin-gcp.plugin metadata` |
| List installed plugins | `tailpipe plugin list` |
| List tables | `tailpipe table list` |

### Notes

- Go 1.24+ is required (`go.mod` specifies toolchain `go1.24.1`).
- `golangci-lint` is installed to `~/go/bin`. Ensure `~/go/bin` is on your `PATH`.
- The first `golangci-lint run` invocation may be slow due to build cache warmup; pass `--timeout 5m` to avoid timeouts.
- `make install` builds the plugin binary and writes it plus `version.json` to `~/.tailpipe/plugins/hub.tailpipe.io/plugins/turbot/gcp@latest/`. The parent directory must exist.
- Tailpipe CLI is installed at `/usr/local/bin/tailpipe`. The `core` plugin is auto-installed on first use.
- Actual log collection (`tailpipe collect`) requires GCP credentials. Tests and builds do not.
- DuckDB is an embedded dependency (via Go bindings); no external database setup is needed.
- The build tag `netgo` is used (see `Makefile`).
