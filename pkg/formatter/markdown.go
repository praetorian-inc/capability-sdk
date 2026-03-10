package formatter

import (
	"context"
	"io"
	"text/template"
)

// MarkdownFormatter buffers findings and writes markdown report on Complete().
type MarkdownFormatter struct {
	w        io.Writer
	toolInfo ToolInfo
	findings []Finding
}

func newMarkdownFormatter(cfg Config) (Formatter, error) {
	return &MarkdownFormatter{
		w:        cfg.Writer,
		toolInfo: cfg.ToolInfo,
		findings: make([]Finding, 0),
	}, nil
}

func (f *MarkdownFormatter) Initialize(ctx context.Context, info ToolInfo) error {
	f.toolInfo = info
	return nil
}

func (f *MarkdownFormatter) Format(ctx context.Context, finding Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.findings = append(f.findings, finding)
	return nil
}

func (f *MarkdownFormatter) Complete(ctx context.Context, summary Summary) error {
	return f.writeReport(summary)
}

func (f *MarkdownFormatter) Close() error {
	return nil
}

func (f *MarkdownFormatter) Len() int {
	return len(f.findings)
}

func (f *MarkdownFormatter) Reset() {
	f.findings = f.findings[:0]
}

var mdTemplate = template.Must(template.New("report").Parse(`# Security Scan Report
{{if .ToolInfo.Name}}
**Tool:** {{.ToolInfo.Name}} {{.ToolInfo.Version}}
{{end}}
## Summary

| Severity | Count |
|----------|-------|
| Critical | {{.Summary.CriticalCount}} |
| High | {{.Summary.HighCount}} |
| Medium | {{.Summary.MediumCount}} |
| Low | {{.Summary.LowCount}} |
| Info | {{.Summary.InfoCount}} |
| **Total** | **{{.Summary.TotalFindings}}** |

## Findings

| Severity | Title | Location |
|----------|-------|----------|
{{range .Findings -}}
| {{.Severity}} | {{.Title}} | {{.Location.String}} |
{{end}}
{{if .Findings}}
## Details
{{range .Findings}}
### {{.Title}}

- **Severity:** {{.Severity}}
- **Rule ID:** {{.RuleID}}
- **Location:** {{.Location.String}}

{{.Description}}
{{if .Remediation}}
**Remediation:** {{.Remediation}}
{{end}}
---
{{end}}
{{end}}
`))

type mdData struct {
	ToolInfo ToolInfo
	Summary  Summary
	Findings []Finding
}

func (f *MarkdownFormatter) writeReport(summary Summary) error {
	data := mdData{
		ToolInfo: f.toolInfo,
		Summary:  summary,
		Findings: f.findings,
	}
	return mdTemplate.Execute(f.w, data)
}
