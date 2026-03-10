package formatter_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalFormatter_SingleFinding(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format:  formatter.FormatTerminal,
		Writer:  &buf,
		Colored: false, // No colors for testable output
	})
	require.NoError(t, err)

	err = f.Format(context.Background(), formatter.Finding{
		ID:       "test-1",
		Title:    "Public S3 Bucket",
		Severity: formatter.SeverityHigh,
		Location: formatter.Location{
			ResourceARN: "arn:aws:s3:::my-bucket",
		},
	})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "[high]")
	assert.Contains(t, output, "Public S3 Bucket")
	assert.Contains(t, output, "arn:aws:s3:::my-bucket")
}

func TestTerminalFormatter_AllSeverities(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format:  formatter.FormatTerminal,
		Writer:  &buf,
		Colored: false,
	})
	require.NoError(t, err)

	severities := []formatter.Severity{
		formatter.SeverityCritical,
		formatter.SeverityHigh,
		formatter.SeverityMedium,
		formatter.SeverityLow,
		formatter.SeverityInfo,
	}

	for _, sev := range severities {
		err = f.Format(context.Background(), formatter.Finding{
			ID:       string(sev),
			Title:    "Test " + string(sev),
			Severity: sev,
		})
		require.NoError(t, err)
	}

	output := buf.String()
	assert.Contains(t, output, "[critical]")
	assert.Contains(t, output, "[high]")
	assert.Contains(t, output, "[medium]")
	assert.Contains(t, output, "[low]")
	assert.Contains(t, output, "[info]")
}

func TestTerminalFormatter_Summary(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatTerminal,
		Writer: &buf,
	})
	require.NoError(t, err)

	err = f.Complete(context.Background(), formatter.Summary{
		TotalFindings: 10,
		CriticalCount: 1,
		HighCount:     3,
		MediumCount:   4,
		LowCount:      2,
		InfoCount:     0,
	})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Total: 10 findings")
	assert.Contains(t, output, "Critical: 1")
}

func TestTerminalFormatter_ContextCancellation(t *testing.T) {
	var buf bytes.Buffer
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatTerminal,
		Writer: &buf,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = f.Format(ctx, formatter.Finding{ID: "test"})
	assert.ErrorIs(t, err, context.Canceled)
}
