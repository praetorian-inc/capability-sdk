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
		writeLines(b, c.Short, "")
	}

	writeLines(b, "- Usage: "+code(usage(c)))
	writeLines(b, "- Aliases: "+aliasCell(c))
	if c.Hidden {
		writeLines(b, "- Hidden: not shown in `--help` output")
	}
	if c.Deprecated != "" {
		writeLines(b, "- Deprecated: "+c.Deprecated)
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
		writeLines(b, "", "### Examples", "", "```bash")
		writeLines(b, strings.Split(strings.TrimRight(dedent(c.Example), "\n"), "\n")...)
		writeLines(b, "```")
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

// renderSubcommandRegion renders the Quick Start subcommand listing: the
// visible top-level commands with their cobra Short descriptions. It states no
// count — the list below it is the count, and a written one would be a second
// thing that can go stale.
func renderSubcommandRegion(s Surface) string {
	root := s.Root()
	children := visible(s.Children(root))

	width := 0
	for _, c := range children {
		if n := len(name(c.Path)); n > width {
			width = n
		}
	}

	var b strings.Builder
	writeLines(&b,
		fmt.Sprintf("%s organizes its functionality into these focused subcommands:", titleFirst(root)),
		"",
		"```bash",
	)
	for _, c := range children {
		writeLines(&b, fmt.Sprintf("%s %-*s # %s", root, width, name(c.Path), c.Short))
	}
	writeLines(&b, "```")
	return b.String()
}

// renderAliasRegion renders the Quick Start alias table. Only subcommands that
// actually declare aliases are listed: this is the most-read part of the
// README, and rows reading "none" contradict the lead-in and add noise. The
// generated reference at Config.MarkdownPath remains the complete reference and
// does list them.
//
// The rows are collected before anything is written, because a CLI whose
// subcommands declare no aliases at all must not be handed a lead-in promising
// aliases over an empty table. In that case the table and its lead-in are
// omitted entirely and the region holds only the pointer to the full
// reference -- which is true of every CLI, keeps the region non-empty so the
// surrounding splice still reads as prose, and says the one useful thing left
// to say.
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

// titleFirst upper-cases the first rune of s, leaving the rest untouched. The
// consumer's root command name is a lowercase binary name, and the README
// sentence it leads reads as a proper noun -- so the upcase is content, not
// decoration. The stdlib's whole-string title-caser is deprecated, and the
// x/text casing package would be a new dependency for one rune, so this decodes
// the rune itself.
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

// code wraps s in markdown code ticks.
func code(s string) string { return "`" + s + "`" }

// cell makes arbitrary help text safe inside a markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

// codeCell wraps a value in code ticks safely inside a table cell. Defaults and flag
// types come from cobra, so they can hold a pipe, a newline or a backtick -- any of
// which breaks the row, and a broken row silently drops a flag from the reference.
// A value containing a backtick needs a longer delimiter plus padding, which is how
// markdown nests code spans.
func codeCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "`") {
		return code(s)
	}
	fence := "``"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	return fence + " " + s + " " + fence
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
