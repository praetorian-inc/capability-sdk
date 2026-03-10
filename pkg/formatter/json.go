package formatter

import (
	"context"
	"encoding/json"
	"io"
)

// JSONFormatter buffers findings and writes as JSON array on Complete().
// Implements BufferedFormatter interface.
type JSONFormatter struct {
	w        io.Writer
	pretty   bool
	findings []Finding
}

func newJSONFormatter(cfg Config) (Formatter, error) {
	return &JSONFormatter{
		w:        cfg.Writer,
		pretty:   cfg.Pretty,
		findings: make([]Finding, 0),
	}, nil
}

func (f *JSONFormatter) Initialize(ctx context.Context, info ToolInfo) error {
	return nil // No initialization needed
}

func (f *JSONFormatter) Format(ctx context.Context, finding Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.findings = append(f.findings, finding)
	return nil
}

func (f *JSONFormatter) Complete(ctx context.Context, summary Summary) error {
	enc := json.NewEncoder(f.w)
	if f.pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(f.findings)
}

func (f *JSONFormatter) Close() error {
	return nil
}

// Len implements BufferedFormatter interface
func (f *JSONFormatter) Len() int {
	return len(f.findings)
}

// Reset implements BufferedFormatter interface
func (f *JSONFormatter) Reset() {
	f.findings = f.findings[:0]
}
