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
// newline that endMark the opening marker line, end is the start of the closing
// marker line.
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
	return begin, endIdx, nil
}
