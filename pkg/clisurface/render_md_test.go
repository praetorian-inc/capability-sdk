package clisurface

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderMarkdownDocumentsEveryCommand(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	md := string(d.renderMarkdown(s))

	assert.True(t, strings.HasPrefix(md, d.generatedNotice()), "the file warns that it is generated")
	assert.Contains(t, md, "Do not edit by hand")
	assert.Contains(t, md, "# tool CLI reference")
	assert.Contains(t, md, "surface hash `"+s.Hash()+"`")
	for _, path := range []string{"tool", "tool scan", "tool guarded", "tool group", "tool group leaf", "tool group old"} {
		assert.Contains(t, md, "## `"+path+"`", "every command gets a section")
	}
	assert.Contains(t, md, "| [`tool scan`](#tool-scan) |", "the index links to the sections")
	assert.True(t, strings.HasSuffix(md, "\n"))
}

func TestRenderMarkdownSeparatesLocalInheritedAndRejectedFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	md := string(d.renderMarkdown(s))
	guarded := section(t, md, "tool guarded")

	assert.Contains(t, guarded, "### Flags")
	assert.Contains(t, guarded, "| `--scan-timeout` |")
	assert.Contains(t, guarded, "### Inherited flags")
	assert.Contains(t, guarded, "| `--json` | `-j` | bool |")
	assert.Contains(t, guarded, "### Rejected flags")
	assert.Contains(t, guarded, "| `--timeout` | --timeout is not valid here; use --scan-timeout |")

	timeoutRows := strings.Count(guarded, "`--timeout`")
	assert.Equal(t, 1, timeoutRows,
		"a rejected flag appears only in the rejected table, never as a usable option")
}

// TestRenderMarkdownAnnotatesHiddenAndDeprecatedCommands covers every
// annotation the markdown reference can emit for a hidden or deprecated
// command, and for a hidden or deprecated flag.
//
// The fixture tree's "old" command is hidden *and* deprecated, so it exercises
// the deprecated arm and can never reach the hidden one -- which is why the
// cases below hand-build a Surface instead. Between them the two annotation
// helpers have no unreached branch left, which is what lets the package doc
// claim that a change to either half fails loudly.
func TestRenderMarkdownAnnotatesHiddenAndDeprecatedCommands(t *testing.T) {
	d := newTestDocs(t)

	t.Run("a command that is both hidden and deprecated", func(t *testing.T) {
		md := string(d.renderMarkdown(Walk(newTestTree())))
		old := section(t, md, "tool group old")

		assert.Contains(t, old, "- Hidden: not shown in `--help` output")
		assert.Contains(t, old, `- Deprecated: use "tool group leaf" instead`)
		assert.Contains(t, md, "the old spelling (deprecated:", "the index flags it too")
		assert.Contains(t, section(t, md, "tool group"), "- Requires a subcommand")

		index := indexRow(t, md, "tool group old")
		assert.Contains(t, index, "(deprecated:")
		assert.NotContains(t, index, "(hidden)",
			"the index annotation is one slot and deprecation takes it; the body says both")
	})

	t.Run("a command that is hidden and not deprecated", func(t *testing.T) {
		md := string(d.renderMarkdown(Surface{Commands: []Command{
			{Path: "tool", Use: "tool", Short: "the tool"},
			{Path: "tool ghost", Use: "ghost", Short: "an internal escape hatch", Runnable: true, Hidden: true},
		}}))

		assert.Contains(t, indexRow(t, md, "tool ghost"), "an internal escape hatch (hidden)")
	})

	t.Run("a hidden flag and a deprecated flag", func(t *testing.T) {
		md := string(d.renderMarkdown(Surface{Commands: []Command{{
			Path: "tool", Use: "tool", Short: "the tool", Runnable: true,
			Flags: []Flag{
				{Name: "internal", Type: "bool", Usage: "an internal switch", Hidden: true},
				{Name: "legacy", Type: "string", Usage: "the old spelling", Deprecated: "use --modern"},
			},
		}}}))

		assert.Contains(t, md, "an internal switch (hidden)")
		assert.Contains(t, md, "the old spelling (deprecated: use --modern)")
	})
}

// indexRow returns the command-index table row for path, so an assertion about
// the index annotation cannot accidentally be satisfied by the command's own
// section further down the document.
func indexRow(t *testing.T, md, path string) string {
	t.Helper()

	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| ["+code(path)+"]") {
			return line
		}
	}
	require.FailNow(t, "no command index row for "+path)
	return ""
}

func TestRenderMarkdownIncludesDedentedExamples(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	scan := section(t, string(d.renderMarkdown(s)), "tool scan")

	assert.Contains(t, scan, "### Examples")
	assert.Contains(t, scan, "```bash\n# scan one host\ntool scan --target host\n```",
		"cobra's two-space example indent is removed so the fence is a plain shell block")
}

func TestRenderMarkdownEscapesTableCells(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{{
		Path: "tool", Use: "tool", Short: "a | b", Runnable: true,
		Flags: []Flag{{Name: "mode", Type: "string", Usage: "cautious | default | aggressive\nsecond line"}},
	}}}

	md := string(d.renderMarkdown(s))

	assert.Contains(t, md, `cautious \| default \| aggressive second line`,
		"pipes are escaped and newlines folded so the markdown table survives")
}

func TestRenderRegionsListsSubcommandsWithoutClaimingACount(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	regions := d.renderRegions(s)
	require.Len(t, regions, 2)
	assert.Equal(t, d.Config().SubcommandsRegion, regions[0].Name, "regions render in a fixed order")
	assert.Equal(t, d.Config().AliasesRegion, regions[1].Name)

	body := regions[0].Body
	assert.Contains(t, body, "Tool organizes its functionality into these focused subcommands:")
	assert.NotRegexp(t, `into \d+ `, body,
		"the list below is the count; a written count is a second thing that can be wrong")
	assert.Contains(t, body, "```bash\ntool group   # a group of things\n")
	assert.Contains(t, body, "tool guarded # rejects --timeout\n")
	assert.Contains(t, body, "tool scan    # scan things\n")
	assert.NotContains(t, body, "tool group leaf", "only top-level subcommands are listed")
}

func TestRenderRegionsAliasTableOmitsCommandsWithoutAliases(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	body := d.renderRegions(s)[1].Body

	assert.Contains(t, body, "| `scan` | `sc`, `scanner` |")
	assert.NotContains(t, body, "*(none)*",
		"the region says 'some subcommands carry aliases', so rows saying 'none' contradict it")
	assert.NotContains(t, body, "| `guarded` |", "a command with no aliases is not listed at all")
	assert.NotContains(t, body, "| `group` |")
	assert.Contains(t, body, "[docs/CLI.md](docs/CLI.md)", "the region links to the full reference")
}

func TestRenderRegionsAliasTableFollowsAliasTransitions(t *testing.T) {
	d := newTestDocs(t)
	base := Surface{Commands: []Command{
		{Path: "tool", Use: "tool"},
		{Path: "tool scan", Use: "scan", Short: "scan things", Aliases: []string{"sc"}},
		{Path: "tool plain", Use: "plain", Short: "no aliases yet"},
	}}

	body := d.renderRegions(base)[1].Body
	require.Contains(t, body, "| `scan` | `sc` |")
	require.NotContains(t, body, "| `plain` |")

	t.Run("a command gaining its first alias appears", func(t *testing.T) {
		gained := base
		gained.Commands = append([]Command(nil), base.Commands...)
		gained.Commands[2].Aliases = []string{"p"}

		body := d.renderRegions(gained)[1].Body

		assert.Contains(t, body, "| `plain` | `p` |",
			"declaring an alias must add the command to the README table")
	})

	t.Run("a command losing its last alias disappears", func(t *testing.T) {
		lost := base
		lost.Commands = append([]Command(nil), base.Commands...)
		lost.Commands[1].Aliases = nil

		body := d.renderRegions(lost)[1].Body

		assert.NotContains(t, body, "| `scan` |",
			"dropping the last alias must remove the command from the README table")
		assert.Contains(t, body, "[docs/CLI.md](docs/CLI.md)",
			"the rest of the region survives an empty table")
	})
}

func TestRenderRegionsSkipsHiddenSubcommands(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{
		{Path: "tool", Use: "tool"},
		{Path: "tool shown", Use: "shown", Short: "visible"},
		{Path: "tool secret", Use: "secret", Short: "hidden", Hidden: true},
	}}

	body := d.renderRegions(s)[0].Body

	assert.Contains(t, body, "tool shown # visible")
	assert.NotContains(t, body, "secret", "hidden commands stay out of the Quick Start listing")
}

func TestUsageIncludesTheArgumentSketch(t *testing.T) {
	assert.Equal(t, "tool scan [flags]", usage(&Command{Path: "tool scan", Use: "scan [flags]"}))
	assert.Equal(t, "tool scan", usage(&Command{Path: "tool scan", Use: "scan"}))
}

func TestDedentLeavesUnindentedTextAlone(t *testing.T) {
	assert.Equal(t, "a\nb", dedent("a\nb"))
	assert.Equal(t, "a\n\nb", dedent("  a\n\n  b"))
}

// section returns the generated reference's section for one command path.
func section(t *testing.T, md, path string) string {
	t.Helper()
	heading := "## `" + path + "`"
	start := strings.Index(md, heading)
	require.GreaterOrEqual(t, start, 0, "section %q must exist", heading)
	rest := md[start+len(heading):]
	if next := strings.Index(rest, "\n## "); next >= 0 {
		return rest[:next]
	}
	return rest
}

// TestAnchorMatchesGitHubsCasing keeps the command-index links working: GitHub lowercases
// heading anchors, so a path with an uppercase letter needs the same treatment.
func TestAnchorMatchesGitHubsCasing(t *testing.T) {
	assert.Equal(t, "tool-scan", anchor("tool scan"))
	assert.Equal(t, "tool-enum-microsoft365", anchor("tool enum Microsoft365"))
}

// TestCodeCellSurvivesTableBreakingValues pins cell escaping for values that come from
// cobra rather than from us. A raw pipe or newline ends the row early, and a broken row
// silently drops a flag from the reference.
func TestCodeCellSurvivesTableBreakingValues(t *testing.T) {
	assert.Equal(t, "`plain`", codeCell("plain"))
	assert.Equal(t, "", codeCell(""))
	// The pipe has to arrive escaped, or it ends the cell and the row loses a column.
	assert.Equal(t, "`a\\|b`", codeCell("a|b"))
	assert.Equal(t, "`one two`", codeCell("one\ntwo"))
	// A value holding a backtick needs a longer delimiter, which is how markdown nests
	// code spans; without it the span closes inside the value.
	assert.Equal(t, "`` a`b ``", codeCell("a`b"))
	assert.Equal(t, "``` a``b ```", codeCell("a``b"))
}

// TestRenderMarkdownEscapesADefaultContainingAPipe is the end-to-end version: the row
// has to stay a five-column row.
func TestRenderMarkdownEscapesADefaultContainingAPipe(t *testing.T) {
	d := newTestDocs(t)
	root := newTestTree()
	scan, _, err := root.Find([]string{"scan"})
	require.NoError(t, err)
	scan.Flags().String("pattern", "a|b", "a default that would break the table")

	for _, line := range strings.Split(string(d.renderMarkdown(Walk(root))), "\n") {
		if strings.Contains(line, "--pattern") {
			assert.Equal(t, 6, strings.Count(line, "|")-strings.Count(line, "\\|"),
				"the row keeps five columns: %s", line)
			return
		}
	}
	t.Fatal("--pattern was not rendered at all")
}

// TestSubcommandRegionLeadsWithTheUpcasedRootName covers the first of T009's two
// fixes: the ported source hard-coded the upstream tool's name in the README
// lead-in, so any other consumer got the wrong brand. The upcase is content --
// the sentence reads as a proper noun -- so the root's own name is title-cased
// rather than emitted verbatim. The brutus case is the parity case: it is the
// name the ported source hard-coded, so a tree rooted there must still produce
// the byte-identical sentence.
func TestSubcommandRegionLeadsWithTheUpcasedRootName(t *testing.T) {
	for _, tc := range []struct {
		name string
		root string
		lead string
	}{
		{name: "the upstream name still renders identically", root: "brutus", lead: "Brutus organizes its functionality into these focused subcommands:"},
		{name: "another consumer gets its own name", root: "capability-sdk", lead: "Capability-sdk organizes its functionality into these focused subcommands:"},
		{name: "a single-rune root upcases too", root: "x", lead: "X organizes its functionality into these focused subcommands:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDocs(t)
			s := Surface{Commands: []Command{
				{Path: tc.root, Use: tc.root},
				{Path: tc.root + " scan", Use: "scan", Short: "scan things"},
			}}

			body := d.renderRegions(s)[0].Body

			assert.True(t, strings.HasPrefix(body, tc.lead+"\n"),
				"the region leads with the consumer's own upcased root name:\n%s", body)
		})
	}

	t.Run("an empty surface has no root and must not panic", func(t *testing.T) {
		d := newTestDocs(t)

		assert.Equal(t, "", titleFirst(""), "titleFirst on an empty root is empty, not a replacement rune")
		assert.NotPanics(t, func() { d.renderRegions(Surface{}) },
			"an empty surface renders an empty listing rather than panicking")
	})
}

// TestRenderRegionsLinksToTheConfiguredMarkdownPath covers the second of T009's two
// fixes: the ported source hard-coded the reference's path in the README link, so a
// consumer that moved its CLI reference got a README pointing at a file that does not
// exist.
func TestRenderRegionsLinksToTheConfiguredMarkdownPath(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.MarkdownPath = "documentation/reference.md" })
	s := Walk(newTestTree())

	body := d.renderRegions(s)[1].Body

	assert.Contains(t, body, "[documentation/reference.md](documentation/reference.md)",
		"the README link follows Config.MarkdownPath")
	assert.NotContains(t, body, "docs/CLI.md",
		"the default path must not survive anywhere in the region once MarkdownPath moves")
}
