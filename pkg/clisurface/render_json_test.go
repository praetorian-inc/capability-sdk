package clisurface

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderJSONShape(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	out, err := d.renderJSON(s)
	require.NoError(t, err)

	text := string(out)
	assert.True(t, strings.HasPrefix(text, "{\n  \"schemaVersion\": 1,\n  \"surfaceHash\": \"sha256:"),
		"schemaVersion and surfaceHash lead the document, two-space indented:\n%s", text[:120])
	assert.True(t, strings.HasSuffix(text, "}\n"), "the file ends with exactly one newline")
	assert.NotContains(t, text, "\n\n", "no blank lines")
	assert.Contains(t, text, `"path": "tool guarded"`)
	assert.Contains(t, text, `"rejected": true`)
	assert.Contains(t, text, `"rejectedReason": "--timeout is not valid here; use --scan-timeout"`)
}

func TestRenderJSONDoesNotEscapeHTML(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{{
		Path: "tool", Use: "tool", Short: "serve on http://127.0.0.1:<port> & wait",
	}}}

	out, err := d.renderJSON(s)
	require.NoError(t, err)

	assert.Contains(t, string(out), "http://127.0.0.1:<port> & wait",
		"help text with angle brackets and ampersands must stay readable")
	assert.NotContains(t, string(out), "\\u003c", "the encoder must not escape angle brackets")
}

func TestRenderJSONOmitsEmptyOptionalFields(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{{Path: "tool", Use: "tool", Short: "a tool", Runnable: true}}}

	out, err := d.renderJSON(s)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "aliases")
	assert.NotContains(t, string(out), "hidden")
	assert.Contains(t, string(out), `"runnable": true`)
}

func TestParseJSONRoundTripsTheSurface(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	out, err := d.renderJSON(s)
	require.NoError(t, err)
	parsed, err := d.ParseJSON(out)
	require.NoError(t, err)

	assert.Equal(t, s, parsed, "the JSON artifact is a lossless copy of the surface")
	assert.Equal(t, s.Hash(), parsed.Hash())
	// The ported suite also asserted Diff(parsed, s) is empty here. Diff lands with
	// diff.go in the next batch; restore that assertion when it does.
}

func TestParseJSONRejectsAnUnknownSchemaVersion(t *testing.T) {
	d := newTestDocs(t)

	_, err := d.ParseJSON([]byte(`{"schemaVersion": 99, "commands": []}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schemaVersion 99")
	assert.Contains(t, err.Error(), testRegenerateCommand, "the error says how to fix it")
}

func TestParseJSONRejectsGarbage(t *testing.T) {
	d := newTestDocs(t)

	_, err := d.ParseJSON([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing cli surface json")
}

// TestRenderJSONIsByteIdenticalAcrossWalks pairs with TestWalkIsDeterministic: the walk
// producing equal surfaces is only useful if rendering them is byte-stable, since the
// committed artifact is compared as bytes.
func TestRenderJSONIsByteIdenticalAcrossWalks(t *testing.T) {
	d := newTestDocs(t)

	first, err := d.renderJSON(Walk(newTestTree()))
	require.NoError(t, err)
	second, err := d.renderJSON(Walk(newTestTree()))
	require.NoError(t, err)

	assert.Equal(t, string(first), string(second))
}

// TestParseJSONRejectsAHashThatDoesNotMatchItsCommands pins the consistency check.
// Downstream consumers pin surfaceHash, so an artifact whose hash does not describe its
// own commands is worse than one with no hash at all: it passes every later comparison.
func TestParseJSONRejectsAHashThatDoesNotMatchItsCommands(t *testing.T) {
	d := newTestDocs(t)

	rendered, err := d.renderJSON(Walk(newTestTree()))
	require.NoError(t, err)

	var lines []string
	for _, line := range strings.Split(string(rendered), "\n") {
		if strings.HasPrefix(line, `  "surfaceHash": "`) {
			line = `  "surfaceHash": "sha256:` + strings.Repeat("0", 64) + `",`
		}
		lines = append(lines, line)
	}

	_, err = d.ParseJSON([]byte(strings.Join(lines, "\n")))
	require.Error(t, err, "a hand-edited artifact must not parse")
	assert.Contains(t, err.Error(), "looks hand-edited")
	assert.Contains(t, err.Error(), testRegenerateCommand)
}

// TestParseJSONWrapsTheDecoderError pins the %w chain the package doc promises: a
// malformed artifact keeps encoding/json's own cause reachable, so a caller can tell a
// truncated file from a schema mismatch without string-matching the message.
func TestParseJSONWrapsTheDecoderError(t *testing.T) {
	d := newTestDocs(t)

	_, err := d.ParseJSON([]byte(`{"schemaVersion": 1, "commands": [`))
	require.Error(t, err)

	var syntaxErr *json.SyntaxError
	require.ErrorAs(t, err, &syntaxErr, "the decoder's *json.SyntaxError stays reachable through %w")
	assert.Contains(t, err.Error(), "parsing cli surface json", "and the wrapper still says what failed")
}
