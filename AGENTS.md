## Agent skills

### Issue tracker

Issues and specs are tracked in GitHub Issues at `0x0034/sentinel`. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Use a single-context layout: root `GLOSSARY.md` and `docs/adr/`. See `docs/agents/domain.md`.

## Project conventions

- Use Go **1.27.2**. `make` pins `GOTOOLCHAIN=go1.27.2`; do not silently upgrade it.
- Entrypoint: `cmd/sentinel`. Application packages live under `internal/`; implementation and behavior are described in `docs/design/rss-feishu.md`.
- Run `make check test build` after behavior changes. Tests use local HTTP servers and temporary SQLite databases; they do not send real robot messages.
- SQLite is the durable store. Run one service instance per database; container data lives in `/data` and must be persisted.
- Keep webhook values in environment variables. Config files contain environment variable names only; do not log webhook URLs or commit credentials.
- Build Docker images for `linux/amd64`. The build base is `registry.cn-hangzhou.aliyuncs.com/0x0034/golang:1.27`; the compiler remains Go 1.27.2 even if the base contains a different patch version.
- The runtime base is `registry.cn-hangzhou.aliyuncs.com/0x0034/alpine:3.22`; use `https://mirrors.aliyun.com/alpine/` for its APK repositories.
- `make image` builds the image; `make push` publishes to `registry.cn-hangzhou.aliyuncs.com/0x0034/sentinel`. Publishing and `send-test` require authorization for the specific task.
- The configured public RSSHub source has returned HTTP 403. Distinguish fixture tests, real robot tests, and live-source checks in verification reports.
