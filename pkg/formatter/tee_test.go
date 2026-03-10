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

func TestTeeFormatter_NoFormatters(t *testing.T) {
	_, err := formatter.NewTee()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one formatter")
}

func TestTeeFormatter_SingleFormatter(t *testing.T) {
	var buf bytes.Buffer
	f, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})

	tee, err := formatter.NewTee(f)
	require.NoError(t, err)

	err = tee.Format(context.Background(), formatter.Finding{
		ID:    "test-1",
		Title: "Test Finding",
	})
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "test-1")
}

func TestTeeFormatter_MultipleFormatters(t *testing.T) {
	var buf1, buf2 bytes.Buffer

	f1, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf1,
	})
	f2, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf2,
	})

	tee, err := formatter.NewTee(f1, f2)
	require.NoError(t, err)

	finding := formatter.Finding{
		ID:    "multi-test",
		Title: "Multi Output Test",
	}

	err = tee.Format(context.Background(), finding)
	require.NoError(t, err)

	// Both buffers should have the finding
	assert.Contains(t, buf1.String(), "multi-test")
	assert.Contains(t, buf2.String(), "multi-test")
}

func TestTeeFormatter_MixedFormats(t *testing.T) {
	var termBuf, jsonBuf bytes.Buffer

	terminal, _ := formatter.New(formatter.Config{
		Format: formatter.FormatTerminal,
		Writer: &termBuf,
	})
	jsonFmt, _ := formatter.New(formatter.Config{
		Format: formatter.FormatJSON,
		Writer: &jsonBuf,
	})

	tee, err := formatter.NewTee(terminal, jsonFmt)
	require.NoError(t, err)

	finding := formatter.Finding{
		ID:       "mixed-1",
		Title:    "Mixed Format Test",
		Severity: formatter.SeverityHigh,
	}

	err = tee.Format(context.Background(), finding)
	require.NoError(t, err)

	err = tee.Complete(context.Background(), formatter.Summary{TotalFindings: 1})
	require.NoError(t, err)

	// Terminal should have human-readable output
	assert.Contains(t, termBuf.String(), "[high]")
	assert.Contains(t, termBuf.String(), "Mixed Format Test")

	// JSON should have valid JSON array
	var findings []formatter.Finding
	err = json.Unmarshal(jsonBuf.Bytes(), &findings)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "mixed-1", findings[0].ID)
}

func TestTeeFormatter_Initialize(t *testing.T) {
	var buf1, buf2 bytes.Buffer

	f1, _ := formatter.New(formatter.Config{
		Format: formatter.FormatTerminal,
		Writer: &buf1,
	})
	f2, _ := formatter.New(formatter.Config{
		Format: formatter.FormatTerminal,
		Writer: &buf2,
	})

	tee, _ := formatter.NewTee(f1, f2)

	err := tee.Initialize(context.Background(), formatter.ToolInfo{
		Name:    "TestTool",
		Version: "1.0.0",
	})
	require.NoError(t, err)

	// Both should have initialization output
	assert.Contains(t, buf1.String(), "TestTool")
	assert.Contains(t, buf2.String(), "TestTool")
}

func TestTeeFormatter_Close(t *testing.T) {
	var buf bytes.Buffer
	f, _ := formatter.New(formatter.Config{
		Format: formatter.FormatNDJSON,
		Writer: &buf,
	})

	tee, _ := formatter.NewTee(f)

	tee.Format(context.Background(), formatter.Finding{ID: "close-test"})

	err := tee.Close()
	require.NoError(t, err)
}
