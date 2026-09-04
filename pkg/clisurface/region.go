package clisurface

import (
	"fmt"
	"strings"
)

// Generated regions let a hand-written document carry generated blocks. The
// markers are HTML comments so they are invisible when the markdown renders.
const (
	regionBeginFormat = "<!-- BEGIN generated: %s -->"
	regionEndFormat   = "<!-- END generated: %s -->"
)

// beginMarker is the opening marker of the named region.
func beginMarker(name string) string { return fmt.Sprintf(regionBeginFormat, name) }

// endMarker is the closing marker of the named region.
func endMarker(name string) string { return fmt.Sprintf(regionEndFormat, name) }

// splice replaces the body of the named region in doc with body. The markers
// themselves are preserved. body is normalized to exactly one trailing newline
// so repeated splices converge.
func splice(doc, name, body string) (string, error) {
	begin, end, err := regionBounds(doc, name)
	if err != nil {
		return "", err
	}
	normalized := strings.TrimRight(strings.ReplaceAll(body, "\r\n", "\n"), "\n") + "\n"
	// Match the document's own line endings. Splicing LF into a CRLF checkout leaves a
	// file that is mixed, which is worse than either convention and shows up as noise
	// in every later diff.
	if dominantNewline(doc) == "\r\n" {
		normalized = strings.ReplaceAll(normalized, "\n", "\r\n")
	}
	return doc[:begin] + normalized + doc[end:], nil
}

// dominantNewline reports the line ending doc mostly uses.
func dominantNewline(doc string) string {
	if strings.Count(doc, "\r\n")*2 > strings.Count(doc, "\n") {
		return "\r\n"
	}
	return "\n"
}

// regionBody returns the current body of the named region.
func regionBody(doc, name string) (string, error) {
	begin, end, err := regionBounds(doc, name)
	if err != nil {
		return "", err
	}
	return doc[begin:end], nil
}

// regionBounds returns the offsets of the region body: begin is just after the
// newline that ends the opening marker line, end is the start of the closing
// marker line. Both markers must be alone on their line, which is what makes
// the second of those true -- see the guard below.
func regionBounds(doc, name string) (begin, end int, err error) {
	beginMark, endMark := beginMarker(name), endMarker(name)

	if n := strings.Count(doc, beginMark); n != 1 {
		return 0, 0, fmt.Errorf("expected exactly one %q marker, found %d", beginMark, n)
	}
	if n := strings.Count(doc, endMark); n != 1 {
		return 0, 0, fmt.Errorf("expected exactly one %q marker, found %d", endMark, n)
	}

	beginIdx := strings.Index(doc, beginMark)
	endIdx := strings.Index(doc, endMark)
	if endIdx < beginIdx {
		return 0, 0, fmt.Errorf("%q appears before %q", endMark, beginMark)
	}

	afterBegin := beginIdx + len(beginMark)
	nl := strings.IndexByte(doc[afterBegin:], '\n')
	if nl < 0 {
		return 0, 0, fmt.Errorf("%q must be followed by a newline", beginMark)
	}
	begin = afterBegin + nl + 1
	// Both markers on one line leaves begin past endIdx. Splicing that produced a
	// document with a duplicated closing marker rather than an error, so say so.
	if begin > endIdx {
		return 0, 0, fmt.Errorf("%q and %q must be on separate lines", beginMark, endMark)
	}

	// Each marker must have its line to itself, and the closing marker is why.
	// endIdx is the marker's own offset, so everything ahead of it on that line
	// falls inside the span splice replaces: a line reading
	// "note <!-- END generated: cli-aliases -->" lost the word "note" on the
	// next Write, with no error, and nothing in the diff to say where it went.
	// Refusing the layout is the only outcome that neither deletes hand-written
	// text nor leaves the region's extent to a rule nobody wrote down, and it is
	// what lets endIdx stand for the start of the closing marker's line.
	//
	// The rule is the same for both markers and admits no whitespace either, so
	// that it can be stated in one sentence and carry one message. Indentation
	// is not merely cosmetic here: whitespace ahead of the closing marker is
	// inside the replaced span like any other text, and four spaces would make
	// the marker line a markdown indented code block, rendering the marker as
	// visible text instead of the comment it is meant to be.
	if err := requireMarkerAlone(doc, beginIdx, beginMark); err != nil {
		return 0, 0, err
	}
	if err := requireMarkerAlone(doc, endIdx, endMark); err != nil {
		return 0, 0, err
	}

	return begin, endIdx, nil
}

// requireMarkerAlone rejects a line that holds anything besides the marker
// found at idx, quoting what it found so the reader can see which line to fix.
func requireMarkerAlone(doc string, idx int, mark string) error {
	before := doc[lineStart(doc, idx):idx]
	after := lineRemainder(doc, idx+len(mark))
	if before == "" && after == "" {
		return nil
	}

	return fmt.Errorf("%q must be alone on its line, but the line also holds %q: move the marker onto a line of its own",
		mark, before+after)
}

// lineStart returns the offset of the first byte of the line holding idx.
func lineStart(doc string, idx int) int {
	return strings.LastIndexByte(doc[:idx], '\n') + 1
}

// lineRemainder returns the rest of the line starting at idx, without the
// terminating newline or the "\r" of a CRLF pair.
func lineRemainder(doc string, idx int) string {
	rest := doc[idx:]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}

	return strings.TrimSuffix(rest, "\r")
}
