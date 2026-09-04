package formatter

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
)

// TerminalFormatter writes findings to terminal with optional color styling.
// Implements StreamingFormatter interface.
type TerminalFormatter struct {
	w      *bufio.Writer
	stdout io.Writer
	color  bool
	styles terminalStyles
}

type terminalStyles struct {
	critical lipgloss.Style
	high     lipgloss.Style
	medium   lipgloss.Style
	low      lipgloss.Style
	info     lipgloss.Style
}

func newTerminalFormatter(cfg Config) (Formatter, error) {
	f := &TerminalFormatter{
		stdout: cfg.Writer,
		w:      bufio.NewWriter(cfg.Writer),
		color:  cfg.Colored,
	}
	if cfg.Colored {
		f.initStyles()
	}
	return f, nil
}

func (f *TerminalFormatter) initStyles() {
	f.styles = terminalStyles{
		critical: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")), // Red
		high:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208")), // Orange
		medium:   lipgloss.NewStyle().Foreground(lipgloss.Color("220")),            // Yellow
		low:      lipgloss.NewStyle().Foreground(lipgloss.Color("33")),             // Blue
		info:     lipgloss.NewStyle().Foreground(lipgloss.Color("245")),            // Gray
	}
}

func (f *TerminalFormatter) Initialize(ctx context.Context, info ToolInfo) error {
	if info.Name != "" {
		if _, err := fmt.Fprintf(f.w, "=== %s v%s ===\n\n", info.Name, info.Version); err != nil {
			return err
		}
		return f.w.Flush()
	}
	return nil
}

func (f *TerminalFormatter) Format(ctx context.Context, finding Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	sev := f.formatSeverity(finding.Severity)
	if _, err := fmt.Fprintf(f.w, "[%s] %s\n", sev, finding.Title); err != nil {
		return err
	}

	loc := finding.Location.String()
	if loc != "" {
		if _, err := fmt.Fprintf(f.w, "  Resource: %s\n", loc); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(f.w); err != nil {
		return err
	}

	return f.w.Flush() // Immediate visibility
}

func (f *TerminalFormatter) formatSeverity(s Severity) string {
	label := string(s)
	if !f.color {
		return label
	}

	switch s {
	case SeverityCritical:
		return f.styles.critical.Render(label)
	case SeverityHigh:
		return f.styles.high.Render(label)
	case SeverityMedium:
		return f.styles.medium.Render(label)
	case SeverityLow:
		return f.styles.low.Render(label)
	default:
		return f.styles.info.Render(label)
	}
}

func (f *TerminalFormatter) Complete(ctx context.Context, summary Summary) error {
	if _, err := fmt.Fprintf(f.w, "---\nTotal: %d findings (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)\n",
		summary.TotalFindings, summary.CriticalCount, summary.HighCount,
		summary.MediumCount, summary.LowCount, summary.InfoCount); err != nil {
		return err
	}
	return f.w.Flush()
}

func (f *TerminalFormatter) Close() error {
	return f.w.Flush()
}

// Flush implements StreamingFormatter interface
func (f *TerminalFormatter) Flush() error {
	return f.w.Flush()
}
