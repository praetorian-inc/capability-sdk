package formatter

import (
	"context"
	"encoding/json"
	"io"
)

// NDJSONFormatter writes findings as newline-delimited JSON (one JSON object per line).
// Implements StreamingFormatter interface.
type NDJSONFormatter struct {
	w       io.Writer
	encoder *json.Encoder
}

func newNDJSONFormatter(cfg Config) (Formatter, error) {
	return &NDJSONFormatter{
		w:       cfg.Writer,
		encoder: json.NewEncoder(cfg.Writer),
	}, nil
}

func (f *NDJSONFormatter) Initialize(ctx context.Context, info ToolInfo) error {
	return nil // No initialization needed for NDJSON
}

func (f *NDJSONFormatter) Format(ctx context.Context, finding Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return f.encoder.Encode(finding) // Automatically adds \n
}

func (f *NDJSONFormatter) Complete(ctx context.Context, summary Summary) error {
	return nil // No-op for streaming format
}

func (f *NDJSONFormatter) Close() error {
	return f.Flush()
}

// Flush implements StreamingFormatter interface
func (f *NDJSONFormatter) Flush() error {
	if flusher, ok := f.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}
