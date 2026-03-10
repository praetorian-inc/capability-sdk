package formatter

import (
	"context"
	"encoding/json"
	"io"
)

// SARIFFormatter buffers findings and writes SARIF 2.1.0 on Complete().
type SARIFFormatter struct {
	w        io.Writer
	toolInfo ToolInfo
	results  []SARIFResult
	rules    map[string]SARIFRule
}

func newSARIFFormatter(cfg Config) (Formatter, error) {
	return &SARIFFormatter{
		w:        cfg.Writer,
		toolInfo: cfg.ToolInfo,
		results:  make([]SARIFResult, 0),
		rules:    make(map[string]SARIFRule),
	}, nil
}

func (f *SARIFFormatter) Initialize(ctx context.Context, info ToolInfo) error {
	f.toolInfo = info
	return nil
}

func (f *SARIFFormatter) Format(ctx context.Context, finding Finding) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Register rule if not seen
	if _, exists := f.rules[finding.RuleID]; !exists {
		f.rules[finding.RuleID] = f.findingToRule(finding)
	}

	f.results = append(f.results, f.findingToResult(finding))
	return nil
}

func (f *SARIFFormatter) Complete(ctx context.Context, summary Summary) error {
	rules := make([]SARIFRule, 0, len(f.rules))
	for _, rule := range f.rules {
		rules = append(rules, rule)
	}

	log := SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           f.toolInfo.Name,
					Version:        f.toolInfo.Version,
					InformationURI: f.toolInfo.URL,
					Rules:          rules,
				},
			},
			Results: f.results,
		}},
	}

	enc := json.NewEncoder(f.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func (f *SARIFFormatter) Close() error {
	return nil
}

func (f *SARIFFormatter) Len() int {
	return len(f.results)
}

func (f *SARIFFormatter) Reset() {
	f.results = f.results[:0]
	f.rules = make(map[string]SARIFRule)
}

func (f *SARIFFormatter) findingToRule(finding Finding) SARIFRule {
	return SARIFRule{
		ID:   finding.RuleID,
		Name: finding.Title,
		ShortDescription: &SARIFMessage{
			Text: finding.Title,
		},
		FullDescription: &SARIFMessage{
			Text: finding.Description,
		},
		DefaultConfig: &SARIFRuleConfig{
			Level: severityToSARIFLevel(finding.Severity),
		},
	}
}

func (f *SARIFFormatter) findingToResult(finding Finding) SARIFResult {
	result := SARIFResult{
		RuleID:  finding.RuleID,
		Level:   severityToSARIFLevel(finding.Severity),
		Message: SARIFMessage{Text: finding.Description},
	}

	// Add location if available
	loc := finding.Location
	if loc.FilePath != "" || loc.ResourceARN != "" {
		sarifLoc := SARIFLocation{}

		if loc.FilePath != "" {
			sarifLoc.PhysicalLocation = &SARIFPhysicalLocation{
				ArtifactLocation: &SARIFArtifactLocation{URI: loc.FilePath},
			}
			if loc.StartLine > 0 {
				sarifLoc.PhysicalLocation.Region = &SARIFRegion{
					StartLine: loc.StartLine,
					EndLine:   loc.EndLine,
				}
			}
		}

		if loc.ResourceARN != "" {
			sarifLoc.LogicalLocations = []SARIFLogicalLocation{{
				FullyQualifiedName: loc.ResourceARN,
				Kind:               loc.ResourceType,
			}}
		}

		result.Locations = []SARIFLocation{sarifLoc}
	}

	return result
}

func severityToSARIFLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
