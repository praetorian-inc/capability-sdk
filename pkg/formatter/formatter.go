package formatter

import (
	"context"
)

// Formatter handles output rendering for security scan results.
// All methods except Close accept context.Context for cancellation support.
type Formatter interface {
	// Initialize prepares the formatter (opens files, writes headers)
	Initialize(ctx context.Context, info ToolInfo) error

	// Format writes a single finding (streaming or buffered depending on implementation)
	Format(ctx context.Context, finding Finding) error

	// Complete finalizes output (closes arrays, writes summary, flushes buffer)
	Complete(ctx context.Context, summary Summary) error

	// Close releases resources (file handles, temp files)
	Close() error
}

// StreamingFormatter writes each finding immediately to output.
// Implementations: TerminalFormatter, NDJSONFormatter
type StreamingFormatter interface {
	Formatter

	// Flush ensures all buffered data (if any) is written to underlying writer
	Flush() error
}

// BufferedFormatter accumulates findings in memory before writing.
// Implementations: JSONFormatter, MarkdownFormatter, SARIFFormatter
type BufferedFormatter interface {
	Formatter

	// Len returns number of buffered findings
	Len() int

	// Reset clears the buffer without writing (useful for testing)
	Reset()
}

// ToolInfo provides scanner/tool metadata for output headers
type ToolInfo struct {
	Name        string
	Version     string
	Description string
	URL         string
}

// Summary provides scan result statistics
type Summary struct {
	TotalFindings int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
}
