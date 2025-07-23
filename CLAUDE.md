# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
RISKEN AWS is a security monitoring system for AWS that searches, analyzes, evaluates, and alerts on discovered threat information. It consists of multiple security scanning services implemented in Go.

## Key Services
The codebase includes 5 main security scanning services:
- **access-analyzer**: AWS Access Analyzer integration
- **admin-checker**: IAM admin permission checker
- **cloudsploit**: CloudSploit security scanner integration
- **guard-duty**: AWS GuardDuty integration
- **portscan**: Port scanning functionality

## Build and Development Commands

### Testing
```bash
# Run all tests
make go-test

# Run tests with code generation
make generate && go test ./...
```

### Linting
```bash
# Run linting
make lint

# Run with specific timeout
GO111MODULE=on GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m
```

### Building
```bash
# Build all services
make build

# Build specific service (e.g., access-analyzer)
make access-analyzer.build

# Build for CI
make build-ci
```

### Docker Operations
```bash
# Push images
make push-image

# Tag images
make tag-image

# Create and push multi-arch manifests
make create-manifest
make push-manifest
```

### Local Development
```bash
# Enqueue test messages to SQS for each service
make enqueue-accessanalyzer
make enqueue-adminchecker
make enqueue-cloudsploit
make enqueue-guardduty
make enqueue-portscan
```

## Architecture

### Service Structure
Each service follows a consistent pattern:
- `cmd/<service>/main.go`: Entry point with configuration and initialization
- `pkg/<service>/`: Core business logic
  - `handler.go`: SQS message handling and orchestration
  - `<service>.go`: AWS API interactions and scanning logic
  - `recommend.go`: Security recommendation generation
  - `*_test.go`: Unit tests

### Communication Pattern
1. Services receive scan requests via AWS SQS queues
2. Each service connects to AWS using assume role credentials
3. Results are sent to RISKEN Core via gRPC
4. Findings include security scores and recommendations

### Key Dependencies
- AWS SDK v2 for all AWS API interactions
- gRPC for communication with RISKEN Core services
- SQS poller for message processing
- DataDog for monitoring and tracing

### Configuration
Services are configured via environment variables:
- `CORE_SVC_ADDR`: RISKEN Core service address
- `DATASOURCE_API_SVC_ADDR`: DataSource API service address
- `AWS_REGION`: Default AWS region
- `SQS_ENDPOINT`: SQS queue endpoint
- Service-specific queue names (e.g., `AWS_ACCESS_ANALYZER_QUEUE_NAME`)

## CloudSploit Configuration
The `cloudsploit.yaml` file contains extensive plugin configurations including:
- Default security scores
- Plugin-specific settings
- Risk descriptions and recommendations
- Tag-based categorization (e.g., pci, reliability)

## Testing Individual Services
To test a specific service:
```bash
# Test access-analyzer package
go test ./pkg/accessanalyzer/...

# Test with verbose output
go test -v ./pkg/accessanalyzer/...

# Test with coverage
go test -cover ./pkg/accessanalyzer/...
```