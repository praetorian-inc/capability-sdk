package formatter

import (
	"fmt"
	"time"
)

// Finding represents a security finding in a format-agnostic way.
// This is the common interchange format all formatters understand.
type Finding struct {
	// Identification
	ID     string `json:"id"`      // Unique finding identifier
	RuleID string `json:"rule_id"` // Detection rule ID

	// Classification
	Severity   Severity   `json:"severity"`             // critical/high/medium/low/info
	Confidence Confidence `json:"confidence,omitempty"` // high/medium/low

	// Content
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	// Location
	Location Location `json:"location"`

	// Provenance
	Source    string    `json:"source"`    // Scanner name
	Timestamp time.Time `json:"timestamp"`

	// Extensibility
	Metadata map[string]any `json:"metadata,omitempty"`

	// Raw domain object (not serialized, for type-specific formatting)
	Raw any `json:"-"`
}

// Severity represents finding severity level
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence represents detection confidence
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Location represents where a finding was discovered.
// Supports cloud resources, code files, and network locations.
type Location struct {
	// Cloud resource fields
	ResourceARN  string `json:"resource_arn,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	Region       string `json:"region,omitempty"`
	AccountID    string `json:"account_id,omitempty"`

	// Code location fields
	FilePath  string `json:"file_path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Column    int    `json:"column,omitempty"`

	// Network location fields
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	URL      string `json:"url,omitempty"`
}

// String returns a human-readable location string
func (l Location) String() string {
	if l.ResourceARN != "" {
		return l.ResourceARN
	}
	if l.FilePath != "" {
		if l.StartLine > 0 {
			return fmt.Sprintf("%s:%d", l.FilePath, l.StartLine)
		}
		return l.FilePath
	}
	if l.Host != "" {
		if l.Port > 0 {
			return fmt.Sprintf("%s://%s:%d", l.Protocol, l.Host, l.Port)
		}
		return l.Host
	}
	return ""
}
