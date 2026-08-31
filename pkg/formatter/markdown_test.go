package formatter_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkdownFormatter_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatMarkdown,
		Writer: &buf,
	})
	require.NoError(t, err)

	err = f.Complete(context.Background(), formatter.Summary{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "# Security Scan Report")
	assert.Contains(t, output, "## Summary")
	assert.Contains(t, output, "| **Total** | **0** |")
}

func TestMarkdownFormatter_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatMarkdown,
		Writer: &buf,
	})
	require.NoError(t, err)

	findings := []formatter.Finding{
		{
			ID:          "f1",
			RuleID:      "public-bucket",
			Title:       "Public S3 Bucket",
			Description: "Bucket allows public access",
			Severity:    formatter.SeverityHigh,
			Location: formatter.Location{
				ResourceARN: "arn:aws:s3:::my-bucket",
			},
		},
		{
			ID:          "f2",
			RuleID:      "weak-password",
			Title:       "Weak Password Policy",
			Description: "Password policy is too weak",
			Severity:    formatter.SeverityMedium,
			Remediation: "Increase password complexity",
		},
	}

	for _, finding := range findings {
		err = f.Format(context.Background(), finding)
		require.NoError(t, err)
	}

	err = f.Complete(context.Background(), formatter.Summary{
		TotalFindings: 2,
		HighCount:     1,
		MediumCount:   1,
	})
	require.NoError(t, err)

	output := buf.String()

	// Check summary table
	assert.Contains(t, output, "| High | 1 |")
	assert.Contains(t, output, "| Medium | 1 |")
	assert.Contains(t, output, "| **Total** | **2** |")

	// Check findings table
	assert.Contains(t, output, "| high | Public S3 Bucket |")

	// Check details section
	assert.Contains(t, output, "### Public S3 Bucket")
	assert.Contains(t, output, "Bucket allows public access")
	assert.Contains(t, output, "**Remediation:** Increase password complexity")
}

func TestMarkdownFormatter_WithToolInfo(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatMarkdown,
		Writer: &buf,
		ToolInfo: formatter.ToolInfo{
			Name:    "Diocletian",
			Version: "1.0.0",
		},
	})
	require.NoError(t, err)

	f.Initialize(context.Background(), formatter.ToolInfo{
		Name:    "Diocletian",
		Version: "1.0.0",
	})

	err = f.Complete(context.Background(), formatter.Summary{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "**Tool:** Diocletian 1.0.0")
}

func TestMarkdownFormatter_BufferedInterface(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatMarkdown,
		Writer: &buf,
	})
	require.NoError(t, err)

	bf, ok := f.(formatter.BufferedFormatter)
	require.True(t, ok, "MarkdownFormatter should implement BufferedFormatter")

	assert.Equal(t, 0, bf.Len())

	f.Format(context.Background(), formatter.Finding{ID: "1"})
	f.Format(context.Background(), formatter.Finding{ID: "2"})
	assert.Equal(t, 2, bf.Len())

	bf.Reset()
	assert.Equal(t, 0, bf.Len())
}

func TestMarkdownFormatter_ContextCancellation(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatMarkdown,
		Writer: &buf,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = f.Format(ctx, formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, context.Canceled)
}
