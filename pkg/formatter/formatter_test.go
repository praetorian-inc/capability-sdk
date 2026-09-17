package formatter_test

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatterInterface_Exists(t *testing.T) {
	// This test verifies the interface compiles
	var _ formatter.Formatter = (*mockFormatter)(nil)
}

type mockFormatter struct{}

func (m *mockFormatter) Initialize(ctx context.Context, info formatter.ToolInfo) error {
	return nil
}

func (m *mockFormatter) Format(ctx context.Context, f formatter.Finding) error {
	return nil
}

func (m *mockFormatter) Complete(ctx context.Context, summary formatter.Summary) error {
	return nil
}

func (m *mockFormatter) Close() error {
	return nil
}

func TestFinding_JSONMarshal(t *testing.T) {
	finding := formatter.Finding{
		ID:          "test-001",
		RuleID:      "aws-s3-public-bucket",
		Severity:    formatter.SeverityHigh,
		Title:       "Public S3 Bucket",
		Description: "Bucket is publicly accessible",
		Location: formatter.Location{
			ResourceARN:  "arn:aws:s3:::test-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
		},
		Source: "aws-config",
	}

	data, err := json.Marshal(finding)
	require.NoError(t, err)

	var decoded formatter.Finding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, finding.ID, decoded.ID)
	assert.Equal(t, finding.Severity, decoded.Severity)
}

func TestNew_UnknownFormat(t *testing.T) {
	_, err := formatter.New(formatter.Config{
		Format: "unknown",
		Writer: io.Discard,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestNew_TerminalFormat(t *testing.T) {
	f, err := formatter.New(formatter.Config{
		Format: formatter.FormatTerminal,
		Writer: io.Discard,
	})
	require.NoError(t, err)
	assert.NotNil(t, f)

	// Verify it implements Formatter
	var _ formatter.Formatter = f
}
