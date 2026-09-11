package clisurface

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// generatedNotice heads every generated markdown artifact.
func (d *Docs) generatedNotice() string {
	return "<!-- Generated from the live cobra command tree by '" + d.cfg.RegenerateCommand + "'. Do not edit by hand. -->"
}

// region is one generated block of a hand-written document.
type region struct {
	Name string
	Body string
}

// renderMarkdown renders the full human-readable reference (Config.MarkdownPath).
func (d *Docs) renderMarkdown(s Surface) []byte {
	root := s.Root()

	var b strings.Builder
	writeLines(&b,
		d.generatedNotice(),
		"",
		"# "+root+" CLI reference",
		"",
		"Every command, alias and flag below is derived from the cobra command tree, not from prose.",
		"Schema version "+strconv.Itoa(schemaVersion)+", surface hash `"+s.Hash()+"`.",
		"",
		"Regenerate with `"+d.cfg.RegenerateCommand+"` after adding, removing or renaming a command or a flag.",
		"",
		"## Command index",
		"",
		"| Command | Aliases | Description |",
		"| --- | --- | --- |",
	)
	for i := range s.Commands {
		c := &s.Commands[i]
		writeLines(&b, "| ["+code(c.Path)+"](#"+anchor(c.Path)+") | "+aliasCell(c)+" | "+cell(indexDescription(c))+" |")
	}

	for i := range s.Commands {
		writeCommand(&b, &s.Commands[i])
	}

	return []byte(b.String())
}

// writeCommand renders one command section of the reference.
func writeCommand(b *strings.Builder, c *Command) {
	writeLines(b, "", "## "+code(c.Path), "")
	if c.Short != "" {
		writeLines(b, escapeAngles(c.Short), "")
	}

	writeUsage(b, c)
	writeLines(b, "- Aliases: "+aliasCell(c))
	if c.Hidden {
		writeLines(b, "- Hidden: not shown in `--help` output")
	}
	if c.Deprecated != "" {
		writeLines(b, "- Deprecated: "+escapeAngles(c.Deprecated))
	}
	if !c.Runnable {
		writeLines(b, "- Requires a subcommand")
	}

	local, inherited, rejected := partitionFlags(c)
	writeFlagTable(b, "Flags", local)
	writeFlagTable(b, "Inherited flags", inherited)

	if len(rejected) > 0 {
		writeLines(b, "", "### Rejected flags", "",
			"These flags reach "+code(c.Path)+" through inheritance, but the command refuses them:",
			"", "| Flag | Why |", "| --- | --- |")
		for _, f := range rejected {
			writeLines(b, "| "+code("--"+f.Name)+" | "+cell(f.RejectedReason)+" |")
		}
	}

	if c.Example != "" {
		body := strings.TrimRight(dedent(c.Example), "\n")
		f := fence(body)
		writeLines(b, "", "### Examples", "", f+"bash")
		writeLines(b, strings.Split(body, "\n")...)
		writeLines(b, f)
	}
}

// writeFlagTable renders a titled flag table, or nothing when there are none.
func writeFlagTable(b *strings.Builder, title string, flags []*Flag) {
	if len(flags) == 0 {
		return
	}
	writeLines(b, "", "### "+title, "", "| Flag | Short | Type | Default | Description |", "| --- | --- | --- | --- | --- |")
	for _, f := range flags {
		short := ""
		if f.Shorthand != "" {
			short = code("-" + f.Shorthand)
		}
		def := ""
		if f.Default != "" {
			def = codeCell(f.Default)
		}
		writeLines(b, "| "+code("--"+f.Name)+" | "+short+" | "+cell(f.Type)+" | "+def+" | "+cell(flagDescription(f))+" |")
	}
}

// renderRegions renders the generated regions of the consumer's README, in a
// fixed order.
func (d *Docs) renderRegions(s Surface) []region {
	return []region{
		{Name: d.cfg.SubcommandsRegion, Body: renderSubcommandRegion(s)},
		{Name: d.cfg.AliasesRegion, Body: d.renderAliasRegion(s)},
	}
}

// renderSubcommandRegion renders the Quick Start subcommand listing: the visible
// top-level commands with their cobra Short descriptions. It states no count -- the
// list is the count, and a written one is a second thing that can go stale.
//
// Rows are collected before anything is written, so a CLI with no visible
// subcommands is not handed a lead-in promising them over an empty fence. There
// both are omitted and the region is empty: the alias region's pointer to the
// full reference already covers a leaf command, and an empty splice keeps the
// required markers without shipping a broken-looking bash block.
func renderSubcommandRegion(s Surface) string {
	root := s.Root()
	children := visible(s.Children(root))
	if len(children) == 0 {
		return ""
	}

	width := 0
	for _, c := range children {
		if n := len(name(c.Path)); n > width {
			width = n
		}
	}

	rows := make([]string, 0, len(children))
	for _, c := range children {
		rows = append(rows, fmt.Sprintf("%s %-*s # %s", root, width, name(c.Path), c.Short))
	}

	var b strings.Builder
	f := fence(strings.Join(rows, "\n"))
	writeLines(&b,
		fmt.Sprintf("%s organizes its functionality into these focused subcommands:", titleFirst(root)),
		"",
		f+"bash",
	)
	writeLines(&b, rows...)
	writeLines(&b, f)
	return b.String()
}

// renderAliasRegion renders the Quick Start alias table. Only subcommands declaring
// aliases are listed: this is the most-read part of the README, and rows reading
// "none" contradict the lead-in. The reference at Config.MarkdownPath stays complete.
//
// Rows are collected before anything is written, so a CLI with no aliases is not
// handed a lead-in promising them over an empty table. There both are omitted and the
// region holds only the pointer to the full reference, keeping it non-empty.
func (d *Docs) renderAliasRegion(s Surface) string {
	root := s.Root()

	rows := make([]string, 0, len(s.Children(root)))
	for _, c := range visible(s.Children(root)) {
		if len(c.Aliases) == 0 {
			continue
		}
		rows = append(rows, "| "+code(name(c.Path))+" | "+aliasCell(c)+" |")
	}

	var b strings.Builder
	if len(rows) > 0 {
		writeLines(&b,
			"Some subcommands carry aliases for discoverability:",
			"",
			"| Subcommand | Aliases |",
			"| --- | --- |",
		)
		writeLines(&b, rows...)
		writeLines(&b, "")
	}
	writeLines(&b,
		"The full reference — every subcommand, alias and flag, including the ones "+
			"hidden from `--help` — is generated into ["+d.cfg.MarkdownPath+"]("+d.cfg.MarkdownPath+").",
	)
	return b.String()
}

// --- helpers ---------------------------------------------------------------

// writeLines appends each line plus a newline.
func writeLines(b *strings.Builder, lines ...string) {
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
}

// visible drops commands hidden from help output.
func visible(cmds []*Command) []*Command {
	out := make([]*Command, 0, len(cmds))
	for _, c := range cmds {
		if !c.Hidden {
			out = append(out, c)
		}
	}
	return out
}

// partitionFlags splits a command's flags into the ones declared on it, the
// usable ones it inherits, and the ones it inherits but refuses.
func partitionFlags(c *Command) (local, inherited, rejected []*Flag) {
	for i := range c.Flags {
		f := &c.Flags[i]
		switch {
		case f.Rejected:
			rejected = append(rejected, f)
		case f.Inherited:
			inherited = append(inherited, f)
		default:
			local = append(local, f)
		}
	}
	return local, inherited, rejected
}

// name returns the last segment of a command path.
func name(path string) string {
	if i := strings.LastIndex(path, " "); i >= 0 {
		return path[i+1:]
	}
	return path
}

// titleFirst upper-cases the first rune of s: the root command name leads a README
// sentence as a proper noun. The stdlib's whole-string title-caser is deprecated and
// x/text would be a new dependency for one rune.
func titleFirst(s string) string {
	if s == "" {
		return ""
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

// usage renders the invocation sketch: the full path with the cobra Use
// string's argument sketch (everything after the command name) appended.
func usage(c *Command) string {
	if i := strings.Index(c.Use, " "); i >= 0 {
		return c.Path + c.Use[i:]
	}
	return c.Path
}

// writeUsage renders the invocation sketch. A single-line Use stays an inline
// code span; a multiline one is a fenced block, because a code span collapses
// the embedded line breaks and the rest of the value becomes one long fragment.
func writeUsage(b *strings.Builder, c *Command) {
	u := usage(c)
	if !strings.Contains(u, "\n") {
		writeLines(b, "- Usage: "+code(u))
		return
	}
	body := strings.TrimRight(u, "\n")
	f := fence(body)
	writeLines(b, "- Usage:", "", f)
	writeLines(b, strings.Split(body, "\n")...)
	writeLines(b, f)
}

// indexDescription is the command-index description, annotated for commands
// that are hidden or deprecated.
func indexDescription(c *Command) string {
	switch {
	case c.Deprecated != "":
		return c.Short + " (deprecated: " + c.Deprecated + ")"
	case c.Hidden:
		return c.Short + " (hidden)"
	default:
		return c.Short
	}
}

// flagDescription is the flag-table description, annotated for flags that are
// hidden or deprecated.
func flagDescription(f *Flag) string {
	switch {
	case f.Deprecated != "":
		return f.Usage + " (deprecated: " + f.Deprecated + ")"
	case f.Hidden:
		return f.Usage + " (hidden)"
	default:
		return f.Usage
	}
}

// aliasCell renders a command's aliases for a table cell.
func aliasCell(c *Command) string {
	if len(c.Aliases) == 0 {
		return "*(none)*"
	}
	out := make([]string, 0, len(c.Aliases))
	for _, a := range c.Aliases {
		out = append(out, code(a))
	}
	return strings.Join(out, ", ")
}

// code wraps s in markdown code ticks, widening the delimiter when s holds a
// backtick. Not cosmetic: a cobra Use string can carry one, and a single-tick wrap
// lets it close the span early, putting the rest of the value back into live
// markdown.
func code(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	fence := "``"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	return fence + " " + s + " " + fence
}

// fence returns the backtick delimiter for a fenced block around body: the standard
// three, widened to one more than the longest run of backticks that starts a line of
// body.
//
// This is code's problem one level up and the more damaging half. A block is closed
// by a line whose run is at least as long as the opener, so a cobra Example -- or a
// Short, which the README subcommand region fences -- carrying a three-backtick line
// ENDS the block there and everything after becomes live markdown, raw HTML included:
// the "<base>" hazard escapeAngles heads off, except that inside a fence nothing
// escaped it.
//
// Leading whitespace is trimmed before measuring rather than bounded at CommonMark's
// three spaces, which over-counts an indented run that could not have closed anything
// -- one backtick of extra width, never a missed breakout. Runs that do not start a
// line are ignored, since a closing fence must begin its line.
func fence(body string) string {
	longest := 0
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimLeft(l, " \t")
		if run := len(l) - len(strings.TrimLeft(l, "`")); run > longest {
			longest = run
		}
	}
	return strings.Repeat("`", max(3, longest+1))
}

// cell makes arbitrary help text safe inside a markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = escapeAngles(s)
	return strings.TrimSpace(s)
}

// escapeAngles neutralizes the HTML angle brackets in cobra-supplied prose.
//
// Markdown passes raw HTML through, and cobra help strings routinely carry
// placeholders spelled "<domain>". An unknown tag has no inner text, so the
// placeholder VANISHES and the reference silently documents something else. One
// naming a real void element -- "<base>", the motivating case -- is worse: GitHub's
// sanitizer strips it, but a local preview or published docs site acts on it, and
// <base> retargets every relative link on the page.
//
// Only "<" and ">" are escaped, deliberately not "&", which would turn a help string
// already reading "&lt;" into "&amp;lt;". So a literal "&lt;" still renders as "<":
// safe, not round-trip faithful. The two replacements are order-independent.
//
// Text destined for a code span or fence must NOT come through here -- "&lt;" renders
// literally there -- which is why usage(), the Default column and the Examples fence
// are left alone.
func escapeAngles(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// codeCell wraps a value in code ticks safely inside a table cell. Cobra defaults
// and types can hold a pipe, newline or backtick, any of which breaks the row and
// silently drops a flag. Widening is code's job; this adds the row-level handling a
// code span cannot express, a pipe closing the cell even from inside one.
func codeCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return code(s)
}

// anchor is the GitHub heading anchor for a "## `path`" heading.
func anchor(path string) string {
	// GitHub lowercases heading anchors, so a path carrying an uppercase letter would
	// otherwise render a link that goes nowhere.
	return strings.ToLower(strings.ReplaceAll(path, " ", "-"))
}

// dedent removes the common leading-space indent cobra examples carry so the
// rendered fence is not indented as a code block twice over.
func dedent(s string) string {
	lines := strings.Split(s, "\n")
	indent := -1
	for _, l := range lines {
		trimmed := strings.TrimLeft(l, " ")
		if trimmed == "" {
			continue
		}
		if n := len(l) - len(trimmed); indent < 0 || n < indent {
			indent = n
		}
	}
	if indent <= 0 {
		return s
	}
	for i, l := range lines {
		if len(l) >= indent {
			lines[i] = l[indent:]
		} else {
			lines[i] = strings.TrimLeft(l, " ")
		}
	}
	return strings.Join(lines, "\n")
}
