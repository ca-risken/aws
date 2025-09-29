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

## DLP (Data Loss Prevention) Configuration
The access-analyzer service includes DLP scanning capabilities for public S3 buckets. Configuration is managed through the `dlp.yaml` file:

### DLP Configuration File
The `dlp.yaml` file defines:
- **Scanning limits**: Maximum files, sizes, and matches per finding
- **File exclusion patterns**: Extensions and directories to skip for performance
- **Detection rules**: Regex patterns for sensitive data (credentials, PII, etc.)

### Environment Variables
- `DLP_CONFIG_PATH`: Path to custom DLP configuration file (optional)
  - If not specified, uses embedded default configuration
  - Default includes common patterns for AWS keys, emails, credit cards, etc.

### DLP Scan Behavior
- Automatically triggered for public S3 buckets detected by Access Analyzer
- Uses hawk-eye scanner with dynamically generated fingerprint files
- Results cached to avoid duplicate scanning of unchanged files
- Configurable limits prevent resource exhaustion on large buckets

### Default Detection Rules
The embedded configuration detects:
- AWS access keys and secret keys
- Email addresses and phone numbers
- Credit card and social security numbers
- API tokens (GitHub, Slack, Google, etc.)
- Database connection strings
- Private keys and JWT tokens

## CloudSploit Configuration
The `cloudsploit.yaml` file contains extensive plugin configurations including:
- Default security scores
- Plugin-specific settings
- Risk descriptions and recommendations
- Tag-based categorization (e.g., pci, reliability)

## Testing Individual Services
To test a specific service:
```bash
# Test access-analyzer package (includes DLP functionality)
go test ./pkg/accessanalyzer/...

# Test with verbose output
go test -v ./pkg/accessanalyzer/...

# Test with coverage
go test -cover ./pkg/accessanalyzer/...
```

### DLP Configuration Testing
Test DLP configuration loading and validation:
```bash
# Test with custom DLP configuration
DLP_CONFIG_PATH=/path/to/custom/dlp.yaml go test ./pkg/accessanalyzer/...

# Test with default embedded configuration
unset DLP_CONFIG_PATH && go test ./pkg/accessanalyzer/...
```

## Unit Testing Standards

### DLP Fingerprint Generation Testing Rules
When testing DLP fingerprint generation functions, follow these standards:

1. **Use Table-Driven Tests**: Structure tests using the table-driven pattern for better maintainability
   ```go
   tests := []struct {
       name       string
       configPath string
       want       string
   }{
       {
           name:       "test case description",
           configPath: "",  // empty for embedded config
           want:       "expected output string",
       },
   }
   ```

2. **Use go-cmp for String Comparison**: Import and use `github.com/google/go-cmp/cmp` for detailed diff output
   ```go
   import "github.com/google/go-cmp/cmp"

   if diff := cmp.Diff(tt.want, gotString); diff != "" {
       t.Errorf("Function() mismatch (-want +got):\n%s", diff)
   }
   ```

3. **Complete String Comparison**: Compare the entire expected output string, not partial matches
   - Ensures exact output format validation
   - Catches unintended changes in output format
   - Provides clear diff when tests fail

4. **Expected Value Accuracy**: Use actual function output to generate expected values
   - Run function to get actual output
   - Use Go's string literal format: `want: "actual output string"`
   - Avoid manual construction of expected strings

### Example Test Structure
```go
func TestGenerateHawkeyeFingerprintYAML(t *testing.T) {
    tests := []struct {
        name       string
        configPath string
        want       string
    }{
        {
            name:       "embedded config generates expected fingerprint",
            configPath: "",
            want:       "Email: \"pattern\"\\nPhone: \"pattern\"\\n...",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            config, err := LoadDLPConfig(tt.configPath)
            if err != nil {
                t.Fatalf("LoadDLPConfig() error = %v", err)
            }

            got, err := config.GenerateHawkeyeFingerprintYAML()
            if err != nil {
                t.Fatalf("GenerateHawkeyeFingerprintYAML() error = %v", err)
            }

            gotString := string(got)
            if diff := cmp.Diff(tt.want, gotString); diff != "" {
                t.Errorf("GenerateHawkeyeFingerprintYAML() mismatch (-want +got):\n%s", diff)
            }
        })
    }
}
```

### Benefits of This Approach
- **Detailed Failure Information**: go-cmp provides exact location and nature of differences
- **Maintainable Test Structure**: Table-driven tests are easy to extend and modify
- **Complete Validation**: Full string comparison ensures output integrity
- **Clear Test Intent**: Each test case clearly describes what it validates

