# Capability SDK

Shared Go SDK for building security capabilities for the Guard platform.

## Packages

### `pkg/capability` - Capability Interface

Defines the standardized interface that security scanners implement.

**Types:**

```go
// Target - what a capability scans
type Target struct {
    Type  TargetType        // domain, ip, port, url, cloud_resource
    Value string            // The target value
    Meta  map[string]string // Additional context
}

// Finding - what a capability discovers
type Finding struct {
    Type     FindingType    // asset, risk, attribute
    Severity Severity       // info, low, medium, high, critical
    Data     map[string]any // Flexible payload
}

// Capability - the interface to implement
type Capability interface {
    Name() string
    Run(ctx context.Context, target Target) ([]Finding, error)
}
```

**Example Implementation:**

```go
type SubdomainScanner struct{}

func (s *SubdomainScanner) Name() string {
    return "subdomain-scanner"
}

func (s *SubdomainScanner) Run(ctx context.Context, target capability.Target) ([]capability.Finding, error) {
    if target.Type != capability.TargetDomain {
        return nil, fmt.Errorf("expected domain, got %s", target.Type)
    }

    // Scan logic here...

    return []capability.Finding{
        {
            Type: capability.FindingAsset,
            Data: map[string]any{
                "dns":   "found.example.com",
                "class": "domain",
            },
        },
    }, nil
}
```

### `pkg/formatter` - Output Formatting

Multi-format output system for rendering scan results.

**Supported Formats:**
- Terminal (streaming, colored via lipgloss)
- JSON (buffered, pretty-print option)
- NDJSON (streaming, newline-delimited)
- Markdown (buffered, template-based reports)
- SARIF 2.1.0 (buffered, GitHub/Azure integration)

**Basic Usage:**

```go
import "github.com/praetorian-inc/capability-sdk/pkg/formatter"

// Create a formatter
f, err := formatter.New(formatter.Config{
    Format: formatter.FormatJSON,
    Writer: os.Stdout,
    Pretty: true,
})
if err != nil {
    return err
}
defer f.Close()

// Format findings
f.Format(ctx, formatter.Finding{
    ID:       "vuln-001",
    Title:    "Security Issue",
    Severity: formatter.SeverityHigh,
})

// Complete with summary
f.Complete(ctx, formatter.Summary{TotalFindings: 1, HighCount: 1})
```

**Converting Capability Findings:**

```go
import (
    "github.com/praetorian-inc/capability-sdk/pkg/capability"
    "github.com/praetorian-inc/capability-sdk/pkg/formatter"
)

// Run capability
findings, err := scanner.Run(ctx, target)

// Convert and format for CLI output
for _, cf := range findings {
    ff := formatter.FromCapabilityFinding(cf)
    f.Format(ctx, ff)
}
```

**Multi-Output (TeeFormatter):**

```go
terminal, _ := formatter.New(formatter.Config{Format: formatter.FormatTerminal, Writer: os.Stdout})
jsonFile, _ := formatter.New(formatter.Config{Format: formatter.FormatJSON, Writer: file})

tee, _ := formatter.NewTee(terminal, jsonFile)
tee.Format(ctx, finding) // Writes to both
```

**Concurrent Submission (Aggregator):**

```go
agg := formatter.NewAggregator(f, 100) // buffer size 100

// From multiple goroutines
go func() { agg.Submit(ctx, finding1) }()
go func() { agg.Submit(ctx, finding2) }()

agg.Close() // Wait for all writes
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     STANDALONE TOOL                                 │
│  Implements: capability.Capability                                  │
│  Produces:   []capability.Finding                                   │
└────────────────────────────┬────────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
┌─────────────────────────┐    ┌─────────────────────────────-────────┐
│   CLI OUTPUT PATH       │    │       CHARIOT INTEGRATION PATH       │
│                         │    │                                      │
│  capability.Finding     │    │  capability.Finding                  │
│         │               │    │         │                            │
│         ▼               │    │         ▼                            │
│  formatter.Finding      │    │  Chariot Adapter (in chariot repo)   │
│  (FromCapabilityFinding)│    │         │                            │
│         │               │    │         ▼                            │
│         ▼               │    │  Tabularium Model (Asset/Risk/Attr)  │
│  Terminal/JSON/SARIF    │    │         │                            │
│                         │    │         ▼                            │
│     stdout/file         │    │     job.Send() → Storage             │
└─────────────────────────┘    └───────────────────────────────-──────┘
```

## Extending Types

### Adding a New Target Type

1. Open issue: "Need `git_repo` target type for X"
2. Backend dev reviews Tabularium mapping
3. Add to `pkg/capability/target.go`:
   ```go
   TargetGitRepo TargetType = "git_repo"
   ```
4. Update `Valid()` method
5. Add tests
6. Update Chariot adapter

### Adding a New Finding Type

1. Open issue: "Need `relationship` finding type for X"
2. Define Data schema
3. Add to `pkg/capability/finding.go`
4. Update converter in `pkg/formatter/capability_converter.go`
5. Add tests

## Modules Using This SDK

- `diocletian` - Cloud security scanner
