package formatter

import (
	"fmt"
	"io"
)

// Format represents available output formats
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatNDJSON   Format = "ndjson"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

// Config controls formatter behavior
type Config struct {
	Format    Format    // Required: output format
	Writer    io.Writer // Required: where to write output
	Colored   bool      // Optional: enable terminal colors (terminal only)
	Pretty    bool      // Optional: indent JSON (json only)
	MaxMemory int       // Optional: max findings in memory before disk spill (buffered only)
	ToolInfo  ToolInfo  // Optional: tool metadata for headers
}

// New creates a formatter based on config.
// Returns error if format is unknown or config is invalid.
func New(cfg Config) (Formatter, error) {
	if cfg.Writer == nil {
		return nil, fmt.Errorf("config.Writer is required")
	}

	switch cfg.Format {
	case FormatTerminal, "":
		// Default to terminal if not specified
		return newTerminalFormatter(cfg)
	case FormatJSON:
		return newJSONFormatter(cfg)
	case FormatNDJSON:
		return newNDJSONFormatter(cfg)
	case FormatMarkdown:
		return newMarkdownFormatter(cfg)
	case FormatSARIF:
		return newSARIFFormatter(cfg)
	default:
		return nil, fmt.Errorf("unknown format: %s", cfg.Format)
	}
}

