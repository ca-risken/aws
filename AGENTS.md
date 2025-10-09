# Repository Guidelines

This guide explains how to work effectively inside the RISKEN AWS codebase. Follow these practices to keep builds green and releases predictable.

## Project Structure & Module Organization
- `cmd/<service>/`: main packages for each scanner entrypoint (access-analyzer, admin-checker, cloudsploit, guard-duty, portscan).
- `pkg/<service>/` and `pkg/common/`: shared service logic, helpers, and gRPC/SQS clients; business code lives here.
- `dockers/` holds container build contexts; `hack/` scripts automate image builds; `codebuild/` contains CI specs.
- `docs/` and `testdata/` store reference material and fixtures—extend them instead of creating ad-hoc folders.
- Root configs such as `cloudsploit.yaml` should remain templates; keep environment secrets in local overrides excluded by `.gitignore`.

## Build, Test, and Development Commands
- `make build IMAGE_TAG=dev`: runs `go test` then builds every service image via `hack/docker-build.sh`.
- `make go-test`: executes `go generate` and `go test ./...`; run before any push.
- `make lint`: invokes `golangci-lint` (5m timeout) with `GOFLAGS=-buildvcs=false`.
- `make generate`: refreshes protobufs and other generated assets.
- Local SQS smoke tests use the sample commands (`make enqueue-*`); point AWS CLI at `http://localhost:9324`.

## Coding Style & Naming Conventions
- Target Go 1.21; format with `gofmt`/`goimports` (tabs, concise camelCase names). CI fails unformatted code.
- Package names stay singular and lowercase; binaries keep hyphenated service names to match Docker images.
- Reuse `pkg/common/logging` for structured logs and `envconfig` structs for configuration parsing.

## Testing Guidelines
- Place table-driven `_test.go` files beside source; pull fixtures from `testdata/`.
- Stub AWS clients with interfaces in `pkg/...` so unit tests remain deterministic; avoid calling live AWS endpoints.
- Validate new work with `make go-test`; add focused integration cases guarded by build tags if external services are required.

## Commit & Pull Request Guidelines
- Follow the conventional prefix pattern seen in history (`feat:`, `fix:`, `chore:`); keep subjects imperative and ≤72 characters.
- Describe motivation, testing evidence, and rollout risks in the body; link related issues or tickets.
- Submit PRs only after `make go-test` and `make lint` succeed; request review from a RISKEN AWS maintainer and include image/tag notes when touching `dockers/` or deployment manifests.

## Security & Configuration Tips
- Never commit real AWS credentials; use local environment files that stay ignored.
- Sanitize account IDs before publishing config examples (`cloudsploit.yaml`, enqueue payloads).
- Keep local queues, registries, and manifests scoped to `localhost` resources to prevent unintended production calls.
