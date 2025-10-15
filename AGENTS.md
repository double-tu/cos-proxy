# Repository Guidelines

## Project Structure & Module Organization
cos-proxy is a Go 1.25 service. Root `proxy.go` hosts the HTTP handler wiring and COS client logic. `controller/s3_controller.go` exposes S3-compatible endpoints via Gin. Configuration templates live in `demo.env`; runtime secrets are injected through a `.env`. Container assets (`Dockerfile`, `docker-compose.yaml`) support image builds. Additional operational notes live in `README.md` and the root S3 API reference text file.

## Build, Test, and Development Commands
- `go run .` boots the proxy locally using the current directory's `*.go` files.
- `go build ./...` produces a production binary named `cos-proxy`.
- `go fmt ./...` formats Go sources (run before committing).
- `go test ./...` executes all package tests with verbose logging.
- `docker-compose up -d` starts the proxy and dependencies defined in compose.

## Coding Style & Naming Conventions
Use Go's default tab indentation and keep lines below 120 chars. Exported symbols use PascalCase and include concise GoDoc comments when part of the public API. Prefer package-scoped helpers over method receivers unless stateful. Stick to descriptive file names like `*_controller.go`. Run `go fmt` (or `goimports` if configured) before pushing. Log messages should be structured and lower case; align with existing `log.Printf` usage until `zerolog` is adopted project-wide.

## Testing Guidelines
Place new `_test.go` files beside the code they cover. Write table-driven tests with the standard `testing` package and use `t.Helper()` for shared assertions. When touching the proxy surface, include integration exercises that stub COS interactions via httptest servers. Target at least 80% coverage for touched packages; confirm with `go test ./... -cover`.

## Commit & Pull Request Guidelines
History shows concise Mandarin imperative messages (translations like "update go" or "optimize"). Continue using short verbs, optionally prefixing scope (e.g., `controller: tighten routing`). Commits should remain focused on one logical change. PRs must summarise impact, link relevant issues, list manual or automated test results (`go test ./...`), and include screenshots or curl transcripts when altering request flows. Flag breaking changes and configuration migrations explicitly.

## Security & Configuration Tips
Never commit populated `.env` files or Tencent credentials. Rotate `TENCENTCLOUD_SECRET_*` keys when handing off environments. Keep `WHITELIST_IPS` minimal and document any temporary entries in the PR. Use internal COS endpoints (`*.cos-internal`) in all configs. Validate container images with `docker scan` before release.
