package clisurface

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// docWithRegion builds a small document carrying one generated region.
func docWithRegion(name, body string) string {
	return strings.Join([]string{
		"# Title",
		"",
		beginMarker(name),
		body,
		endMarker(name),
		"",
		"hand-written tail",
		"",
	}, "\n")
}

func TestSpliceReplacesOnlyTheRegionBody(t *testing.T) {
	doc := docWithRegion("cli-subcommands", "stale body")

	out, err := splice(doc, "cli-subcommands", "fresh body")
	require.NoError(t, err)

	assert.Equal(t, docWithRegion("cli-subcommands", "fresh body"), out)
	assert.Contains(t, out, "hand-written tail", "text outside the region is untouched")
}

func TestSpliceIsIdempotent(t *testing.T) {
	doc := docWithRegion("cli-aliases", "old")

	once, err := splice(doc, "cli-aliases", "new\nlines\n")
	require.NoError(t, err)
	twice, err := splice(once, "cli-aliases", "new\nlines\n")
	require.NoError(t, err)

	assert.Equal(t, once, twice, "splicing the same body twice must converge")
	assert.NotContains(t, once, "new\n\n</", "the body keeps exactly one trailing newline")
}

func TestRegionBodyRoundTrips(t *testing.T) {
	doc := docWithRegion("cli-aliases", "line one\nline two")

	body, err := regionBody(doc, "cli-aliases")
	require.NoError(t, err)
	assert.Equal(t, "line one\nline two\n", body)
}

func TestSpliceRejectsBrokenMarkers(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name:    "missing begin marker",
			doc:     "text\n" + endMarker("cli-aliases") + "\n",
			wantErr: `expected exactly one "<!-- BEGIN generated: cli-aliases -->" marker, found 0`,
		},
		{
			name:    "missing end marker",
			doc:     beginMarker("cli-aliases") + "\nbody\n",
			wantErr: `expected exactly one "<!-- END generated: cli-aliases -->" marker, found 0`,
		},
		{
			name:    "duplicated region",
			doc:     docWithRegion("cli-aliases", "a") + docWithRegion("cli-aliases", "b"),
			wantErr: "found 2",
		},
		{
			name:    "markers out of order",
			doc:     endMarker("cli-aliases") + "\nbody\n" + beginMarker("cli-aliases") + "\n",
			wantErr: "appears before",
		},
		{
			name:    "begin marker not on its own line",
			doc:     beginMarker("cli-aliases") + " trailing text without newline" + endMarker("cli-aliases"),
			wantErr: "must be followed by a newline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := splice(tt.doc, "cli-aliases", "body")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMarkersAreHTMLComments(t *testing.T) {
	assert.Equal(t, "<!-- BEGIN generated: cli-subcommands -->", beginMarker("cli-subcommands"))
	assert.Equal(t, "<!-- END generated: cli-aliases -->", endMarker("cli-aliases"))
}

// TestSpliceRejectsMarkersOnOneLine pins the bounds guard. Both markers on a single line
// used to splice into a document carrying a duplicated closing marker instead of failing.
func TestSpliceRejectsMarkersOnOneLine(t *testing.T) {
	doc := beginMarker("cli-subcommands") + " " + endMarker("cli-subcommands") + "\n"

	_, err := splice(doc, "cli-subcommands", "body")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "separate lines")
}

// TestSplicePreservesCRLF pins the newline convention. Splicing LF regions into a CRLF
// checkout produced a mixed file, which is worse than either and shows up as noise in
// every later diff.
func TestSplicePreservesCRLF(t *testing.T) {
	lf := strings.Join([]string{
		"# tool", "", beginMarker("cli-subcommands"), "old", endMarker("cli-subcommands"), "tail", "",
	}, "\n")
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")

	out, err := splice(crlf, "cli-subcommands", "line one\nline two")
	require.NoError(t, err)

	assert.Contains(t, out, "line one\r\nline two\r\n")
	assert.Equal(t, strings.Count(out, "\n"), strings.Count(out, "\r\n"), "every newline stays CRLF")

	// And an LF document is left alone.
	out, err = splice(lf, "cli-subcommands", "line one\nline two")
	require.NoError(t, err)
	assert.NotContains(t, out, "\r")
}

// TestSpliceRejectsADuplicateRegionPair pins the duplicate-pair guard. "First pair wins"
// would silently ignore the second block, and "first BEGIN to last END" would eat the
// hand-written prose sitting between the two pairs -- so a second pair is an error.
func TestSpliceRejectsADuplicateRegionPair(t *testing.T) {
	doc := strings.Join([]string{
		beginMarker("cli-aliases"), "first", endMarker("cli-aliases"),
		"",
		"hand-written prose between the two pairs",
		"",
		beginMarker("cli-aliases"), "second", endMarker("cli-aliases"),
		"",
	}, "\n")

	out, err := splice(doc, "cli-aliases", "body")

	require.Error(t, err)
	assert.Contains(t, err.Error(), beginMarker("cli-aliases"),
		"both markers are duplicated, so the begin-marker guard fires first and names its own marker")
	assert.Contains(t, err.Error(), "found 2")
	assert.Empty(t, out, "a rejected splice returns no document to write")
}

// TestSpliceRejectsANestedRegionPair pins the nesting guard: a same-name pair inside
// another is ambiguous about which body to replace, so it is rejected rather than
// resolved by a rule nobody wrote down.
func TestSpliceRejectsANestedRegionPair(t *testing.T) {
	doc := strings.Join([]string{
		beginMarker("cli-aliases"),
		"outer",
		beginMarker("cli-aliases"),
		"inner",
		endMarker("cli-aliases"),
		endMarker("cli-aliases"),
		"",
	}, "\n")

	out, err := splice(doc, "cli-aliases", "body")

	require.Error(t, err)
	assert.Contains(t, err.Error(), beginMarker("cli-aliases"),
		"both markers are duplicated, so the begin-marker guard fires first and names its own marker")
	assert.Contains(t, err.Error(), "found 2")
	assert.Empty(t, out, "a rejected splice returns no document to write")
}

// TestSpliceRejectsADuplicatedBeginMarkerAlone locks the begin-marker guard on its own.
// A README carrying two BEGIN markers and a single END would otherwise splice between the
// first BEGIN and that single END, eating the second marker and every hand-written line
// between them. Both markers duplicated cannot pin this: the end-marker guard alone still
// rejects that document, so only the asymmetric case holds this guard individually.
func TestSpliceRejectsADuplicatedBeginMarkerAlone(t *testing.T) {
	doc := strings.Join([]string{
		"# Title",
		"",
		beginMarker("cli-aliases"),
		"first body",
		"",
		"hand-written prose between the two BEGIN markers",
		"",
		beginMarker("cli-aliases"),
		"second body",
		endMarker("cli-aliases"),
		"",
		"hand-written tail",
		"",
	}, "\n")

	out, err := splice(doc, "cli-aliases", "body")

	require.Error(t, err)
	assert.Contains(t, err.Error(), beginMarker("cli-aliases"),
		"the rejection must name the begin marker, not merely a count")
	assert.NotContains(t, err.Error(), endMarker("cli-aliases"),
		"the single end marker is well-formed and must not be blamed")
	assert.Contains(t, err.Error(), "found 2")
	assert.Empty(t, out, "a rejected splice returns no document to write")
}

// TestSpliceRejectsADuplicatedEndMarkerAlone locks the end-marker guard on its own.
// A single BEGIN with two ENDs would otherwise splice to the first END and leave the
// stray second one behind as committed content. Both markers duplicated cannot pin this:
// the begin-marker guard runs first and rejects that document before this one is reached.
func TestSpliceRejectsADuplicatedEndMarkerAlone(t *testing.T) {
	doc := strings.Join([]string{
		"# Title",
		"",
		beginMarker("cli-aliases"),
		"body",
		endMarker("cli-aliases"),
		"",
		"hand-written prose after the first pair",
		"",
		endMarker("cli-aliases"),
		"",
		"hand-written tail",
		"",
	}, "\n")

	out, err := splice(doc, "cli-aliases", "body")

	require.Error(t, err)
	assert.Contains(t, err.Error(), endMarker("cli-aliases"),
		"the rejection must name the end marker, not merely a count")
	assert.NotContains(t, err.Error(), beginMarker("cli-aliases"),
		"the single begin marker is well-formed and must not be blamed")
	assert.Contains(t, err.Error(), "found 2")
	assert.Empty(t, out, "a rejected splice returns no document to write")
}
