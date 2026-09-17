package formatter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSARIFFormatter_ValidStructure(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatSARIF,
		Writer: &buf,
		ToolInfo: formatter.ToolInfo{
			Name:    "diocletian",
			Version: "1.0.0",
		},
	})
	require.NoError(t, err)

	err = f.Initialize(context.Background(), formatter.ToolInfo{
		Name:    "diocletian",
		Version: "1.0.0",
	})
	require.NoError(t, err)

	err = f.Format(context.Background(), formatter.Finding{
		ID:          "test-1",
		RuleID:      "public-s3-bucket",
		Title:       "Public S3 Bucket",
		Description: "Bucket is publicly accessible",
		Severity:    formatter.SeverityHigh,
		Location: formatter.Location{
			ResourceARN:  "arn:aws:s3:::my-bucket",
			ResourceType: "AWS::S3::Bucket",
		},
	})
	require.NoError(t, err)

	err = f.Complete(context.Background(), formatter.Summary{TotalFindings: 1})
	require.NoError(t, err)

	// Parse and validate structure
	var sarif map[string]any
	err = json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", sarif["version"])
	assert.Contains(t, sarif["$schema"], "sarif-schema-2.1.0")

	runs := sarif["runs"].([]any)
	assert.Len(t, runs, 1)

	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	assert.Equal(t, "diocletian", driver["name"])

	results := run["results"].([]any)
	assert.Len(t, results, 1)
}

func TestSARIFFormatter_SeverityMapping(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatSARIF,
		Writer: &buf,
	})
	require.NoError(t, err)

	severities := []struct {
		sev   formatter.Severity
		level string
	}{
		{formatter.SeverityCritical, "error"},
		{formatter.SeverityHigh, "error"},
		{formatter.SeverityMedium, "warning"},
		{formatter.SeverityLow, "note"},
		{formatter.SeverityInfo, "note"},
	}

	for _, tc := range severities {
		buf.Reset()
		if bf, ok := f.(formatter.BufferedFormatter); ok {
			bf.Reset()
		}

		f.Format(context.Background(), formatter.Finding{
			RuleID:   "test",
			Severity: tc.sev,
		})
		f.Complete(context.Background(), formatter.Summary{})

		var sarif map[string]any
		json.Unmarshal(buf.Bytes(), &sarif)

		runs := sarif["runs"].([]any)
		run := runs[0].(map[string]any)
		results := run["results"].([]any)
		result := results[0].(map[string]any)

		assert.Equal(t, tc.level, result["level"], "severity %v should map to level %s", tc.sev, tc.level)
	}
}

func TestSARIFFormatter_RuleDeduplication(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatSARIF,
		Writer: &buf,
	})
	require.NoError(t, err)

	// Add multiple findings with same rule
	for i := 0; i < 3; i++ {
		f.Format(context.Background(), formatter.Finding{
			RuleID:   "same-rule",
			Title:    "Same Rule",
			Severity: formatter.SeverityHigh,
		})
	}

	f.Complete(context.Background(), formatter.Summary{})

	var sarif map[string]any
	json.Unmarshal(buf.Bytes(), &sarif)

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules := driver["rules"].([]any)

	// Should only have 1 rule despite 3 results
	assert.Len(t, rules, 1)

	results := run["results"].([]any)
	assert.Len(t, results, 3)
}

func TestSARIFFormatter_PhysicalLocation(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatSARIF,
		Writer: &buf,
	})
	require.NoError(t, err)

	f.Format(context.Background(), formatter.Finding{
		RuleID:      "test-rule",
		Title:       "Test Finding",
		Description: "Test description",
		Severity:    formatter.SeverityHigh,
		Location: formatter.Location{
			FilePath:  "src/config.yml",
			StartLine: 10,
			EndLine:   15,
		},
	})

	f.Complete(context.Background(), formatter.Summary{})

	var sarif map[string]any
	json.Unmarshal(buf.Bytes(), &sarif)

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	result := results[0].(map[string]any)

	locations := result["locations"].([]any)
	require.Len(t, locations, 1)

	location := locations[0].(map[string]any)
	physicalLoc := location["physicalLocation"].(map[string]any)

	artifact := physicalLoc["artifactLocation"].(map[string]any)
	assert.Equal(t, "src/config.yml", artifact["uri"])

	region := physicalLoc["region"].(map[string]any)
	assert.Equal(t, float64(10), region["startLine"])
	assert.Equal(t, float64(15), region["endLine"])
}

func TestSARIFFormatter_LogicalLocation(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatSARIF,
		Writer: &buf,
	})
	require.NoError(t, err)

	f.Format(context.Background(), formatter.Finding{
		RuleID:      "test-rule",
		Title:       "Test Finding",
		Description: "Test description",
		Severity:    formatter.SeverityHigh,
		Location: formatter.Location{
			ResourceARN:  "arn:aws:s3:::my-bucket",
			ResourceType: "AWS::S3::Bucket",
		},
	})

	f.Complete(context.Background(), formatter.Summary{})

	var sarif map[string]any
	json.Unmarshal(buf.Bytes(), &sarif)

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	result := results[0].(map[string]any)

	locations := result["locations"].([]any)
	require.Len(t, locations, 1)

	location := locations[0].(map[string]any)
	logicalLocs := location["logicalLocations"].([]any)
	require.Len(t, logicalLocs, 1)

	logicalLoc := logicalLocs[0].(map[string]any)
	assert.Equal(t, "arn:aws:s3:::my-bucket", logicalLoc["fullyQualifiedName"])
	assert.Equal(t, "AWS::S3::Bucket", logicalLoc["kind"])
}
