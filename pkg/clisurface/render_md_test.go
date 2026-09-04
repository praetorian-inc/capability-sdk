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

// TestRenderRegionsAliasTableIsByteExactWhenAliasesExist pins the whole
// non-empty body, not just the row. Collecting the rows before writing moved
// the lead-in, the header and the blank line before the closing sentence
// behind a condition, and this package's committed artifacts are compared
// byte-for-byte, so a stray blank line is a regression, not cosmetics.
func TestRenderRegionsAliasTableIsByteExactWhenAliasesExist(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	body := d.renderRegions(s)[1].Body

	assert.Equal(t, strings.Join([]string{
		"Some subcommands carry aliases for discoverability:",
		"",
		"| Subcommand | Aliases |",
		"| --- | --- |",
		"| `scan` | `sc`, `scanner` |",
		"",
		"The full reference — every subcommand, alias and flag, including the ones " +
			"hidden from `--help` — is generated into [docs/CLI.md](docs/CLI.md).",
		"",
	}, "\n"), body)
}

// TestRenderRegionsAliasTableDropsItsLeadInWhenNothingHasAliases is the case
// the unconditional lead-in got wrong: a CLI whose subcommands declare no
// aliases used to be handed "Some subcommands carry aliases for
// discoverability:" above an empty two-line table -- a claim contradicted by
// the very table meant to support it. The lead-in and the table now go
// together, and the pointer to the full reference stays because it is true of
// every CLI and keeps the region non-empty prose.
func TestRenderRegionsAliasTableDropsItsLeadInWhenNothingHasAliases(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{
		{Path: "tool", Use: "tool"},
		{Path: "tool scan", Use: "scan", Short: "scan things"},
		{Path: "tool plain", Use: "plain", Short: "no aliases anywhere"},
	}}

	body := d.renderRegions(s)[1].Body

	assert.Equal(t,
		"The full reference — every subcommand, alias and flag, including the ones "+
			"hidden from `--help` — is generated into [docs/CLI.md](docs/CLI.md).\n",
		body, "with no rows to show, the region is the pointer sentence and nothing else")
	assert.NotContains(t, body, "aliases for discoverability",
		"no lead-in may promise aliases the table cannot show")
	assert.NotContains(t, body, "| Subcommand | Aliases |", "and no header for a table with no rows")
	assert.NotEmpty(t, body, "the region still has to hold something for the splice to read as prose")
}

// TestRenderRegionsAliasTableHidesTheTableWhenOnlyHiddenCommandsHaveAliases
// covers the boundary between the visibility filter and the emptiness test:
// the alias-bearing command exists but is filtered out, so the row count -- not
// the alias count -- has to be what decides.
func TestRenderRegionsAliasTableHidesTheTableWhenOnlyHiddenCommandsHaveAliases(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{
		{Path: "tool", Use: "tool"},
		{Path: "tool secret", Use: "secret", Short: "hidden", Hidden: true, Aliases: []string{"s"}},
	}}

	body := d.renderRegions(s)[1].Body

	assert.NotContains(t, body, "aliases for discoverability")
	assert.NotContains(t, body, "`s`", "a hidden command's aliases stay out of the README")
	assert.Contains(t, body, "[docs/CLI.md](docs/CLI.md)")
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

// --- angle-bracket escaping -------------------------------------------------

// newAngleSurface is the shape the escaping fix was measured on: a cobra help
// string carrying an argument placeholder spelled with angle brackets, in every
// slot the markdown renderer can put one. Markdown passes raw HTML through, so
// an unescaped "<domain>" is read as an unknown tag and VANISHES -- the
// generated reference then documents a description other than the one it was
// handed.
//
// The surface is hand-built rather than walked from cobra because a flag Type
// and a RejectedReason are the two columns a cobra tree cannot be made to fill
// with angle brackets on demand, and both of them reach the page through cell().
func newAngleSurface() Surface {
	return Surface{Commands: []Command{
		{Path: "tool", Use: "tool", Short: "the tool", Runnable: true},
		{
			Path:       "tool scan",
			Use:        "scan <domain>",
			Short:      "scan a <domain> for issues",
			Deprecated: `use "tool probe <domain>" instead`,
			Runnable:   true,
			Example:    "  tool scan <domain>",
			Flags: []Flag{
				{Name: "target", Type: "<host:port>", Usage: "target as <host>:<port>", Default: "<none>"},
				{
					Name: "timeout", Type: "duration", Usage: "per-target timeout",
					Inherited: true, Rejected: true,
					RejectedReason: "not usable here; pass <scan-timeout> instead",
				},
			},
		},
	}}
}

// tableRow returns the one markdown table row that begins with token, so an
// assertion about a single column cannot be satisfied by prose elsewhere in the
// document -- which is exactly how an escaping test passes while the column it
// names is still raw.
func tableRow(t *testing.T, md, token string) string {
	t.Helper()

	var found []string
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| "+token+" |") {
			found = append(found, line)
		}
	}
	require.Len(t, found, 1, "exactly one table row must begin with %q", token)
	return found[0]
}

// TestRenderMarkdownEscapesAngleBracketsInEveryDescriptionColumn covers the
// four cells cell() feeds: the command-index Description, the flag-table
// Description, the flag-table Type, and the rejected-flag Why. Before the fix
// cell() escaped a newline and a pipe but not an angle bracket, so a placeholder
// in any of them was swallowed by the renderer.
func TestRenderMarkdownEscapesAngleBracketsInEveryDescriptionColumn(t *testing.T) {
	d := newTestDocs(t)

	md := string(d.renderMarkdown(newAngleSurface()))

	index := indexRow(t, md, "tool scan")
	assert.Contains(t, index, `scan a &lt;domain&gt; for issues (deprecated: use "tool probe &lt;domain&gt;" instead)`,
		"the command-index Description column is escaped, annotation included")
	assert.NotContains(t, index, "<domain>", "no raw placeholder survives in the index row")

	target := tableRow(t, md, "`--target`")
	assert.Contains(t, target, "| &lt;host:port&gt; |", "the Type column is escaped")
	assert.Contains(t, target, "| target as &lt;host&gt;:&lt;port&gt; |", "the flag Description column is escaped")
	assert.NotContains(t, target, "<host", "no raw placeholder survives in the flag row's escaped columns")

	rejected := tableRow(t, md, "`--timeout`")
	assert.Contains(t, rejected, "| not usable here; pass &lt;scan-timeout&gt; instead |",
		"the rejected-flag Why column is escaped")
	assert.NotContains(t, rejected, "<scan-timeout>")
}

// TestRenderMarkdownEscapesTheCommandBodyProse covers the two slots that never
// went through cell() at all: Short is written as a body paragraph and
// Deprecated as a body line, so both reached the page raw however well the
// table cells were escaped.
func TestRenderMarkdownEscapesTheCommandBodyProse(t *testing.T) {
	d := newTestDocs(t)

	scan := section(t, string(d.renderMarkdown(newAngleSurface())), "tool scan")

	assert.Contains(t, scan, "\nscan a &lt;domain&gt; for issues\n",
		"the Short paragraph is escaped, and it is a paragraph rather than a cell")
	assert.Contains(t, scan, "\n- Deprecated: use \"tool probe &lt;domain&gt;\" instead\n",
		"the Deprecated line is escaped too")
	assert.NotContains(t, scan, "scan a <domain> for issues")
	assert.NotContains(t, scan, "tool probe <domain>")
}

// TestRenderMarkdownLeavesCodeSpansAndFencesUnescaped is the negative half, and
// it is the one that matters most: angle brackets are already inert inside a
// code span or a fence, so escaping them there renders the four literal
// characters "&lt;" to the reader. Over-escaping is the likelier future
// regression -- it is what a well-meaning "escape everything" change produces --
// and nothing else in the suite would catch it.
func TestRenderMarkdownLeavesCodeSpansAndFencesUnescaped(t *testing.T) {
	d := newTestDocs(t)
	s := newAngleSurface()

	md := string(d.renderMarkdown(s))
	scan := section(t, md, "tool scan")

	assert.Contains(t, scan, "- Usage: `tool scan <domain>`\n",
		"usage() renders into a code span, where the brackets are already inert")
	assert.Contains(t, tableRow(t, md, "`--target`"), "| `<none>` |",
		"the Default column is a code span, so it keeps the value cobra gave it")
	assert.Contains(t, scan, "```bash\ntool scan <domain>\n```",
		"the Examples fence is verbatim shell: an escaped bracket there is a wrong command")

	region := d.renderRegions(s)[0].Body
	assert.Contains(t, region, "tool scan # scan a <domain> for issues",
		"the subcommand region writes Short inside a bash fence, so it stays raw there")
	assert.NotContains(t, region, "&lt;", "nothing in the region is escaped")
}

// TestEscapeAnglesLeavesTheAmpersandAlone pins a deliberate decision, not an
// oversight. "<" and ">" are the whole escape set: the pair is order-independent
// (neither "&lt;" nor "&gt;" contains an angle bracket, so neither can feed the
// other) and self-terminating, while "&" is the one character whose escaping
// creates the double-escape problem -- it would rewrite a help string that
// already reads "&lt;" into "&amp;lt;". CommonMark renders a bare "&" literally,
// so escaping it buys nothing and costs correctness.
//
// A later "helpful" ampersand escape must fail here rather than quietly ship.
func TestEscapeAnglesLeavesTheAmpersandAlone(t *testing.T) {
	assert.Equal(t, "&lt;domain&gt;", escapeAngles("<domain>"))
	assert.Equal(t, "", escapeAngles(""))
	assert.Equal(t, "no markup here", escapeAngles("no markup here"))

	assert.Equal(t, "a & b", escapeAngles("a & b"),
		"a bare ampersand is rendered literally by CommonMark and is left as written")
	assert.Equal(t, "&lt;", escapeAngles("&lt;"),
		"an input that already reads &lt; must not become &amp;lt;")
	assert.Equal(t, "&amp;", escapeAngles("&amp;"))
	assert.Equal(t, "&lt;a&gt; &amp; &lt;b&gt;", escapeAngles("<a> &amp; <b>"),
		"escaping the brackets around an existing entity leaves that entity untouched")

	assert.Equal(t, "&gt;&lt;", escapeAngles("><"),
		"the two replacements are order-independent: neither output contains an angle bracket")
}

// TestRenderMarkdownDoesNotDoubleEscape is the end-to-end companion: a help
// string that already carries an entity comes through the renderer unchanged.
func TestRenderMarkdownDoesNotDoubleEscape(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{{
		Path: "tool", Use: "tool", Runnable: true,
		Short: "already reads &lt;domain&gt;, and a & b is bare",
		Flags: []Flag{{Name: "mode", Type: "string", Usage: "either &lt;fast&gt; or a & b"}},
	}}}

	md := string(d.renderMarkdown(s))

	assert.Contains(t, md, "already reads &lt;domain&gt;, and a & b is bare")
	assert.Contains(t, md, "either &lt;fast&gt; or a & b")
	assert.NotContains(t, md, "&amp;",
		"the ampersand is the only character whose escaping double-escapes, so it is not escaped")
	assert.NotContains(t, md, "&amp;lt;")
}

// --- backtick-bearing values ------------------------------------------------

// TestCodeWidensItsDelimiterAroundABacktick pins the widening at the helper
// every code span in the document goes through, not just the Default column it
// used to live in.
func TestCodeWidensItsDelimiterAroundABacktick(t *testing.T) {
	assert.Equal(t, "`plain`", code("plain"))
	assert.Equal(t, "`` a`b ``", code("a`b"))
	assert.Equal(t, "``` a``b ```", code("a``b"))
	assert.Equal(t, "```` a```b ````", code("a```b"))
}

// TestRenderMarkdownWidensTheUsageSpanAroundABacktickInUse is the case that
// motivated moving the widening into code(): a cobra Use string may carry a
// backtick, and a plain single-tick wrap closes the span on it -- putting the
// rest of the value, angle-bracket placeholders included, back into live
// markdown. usage() deliberately does not escape, precisely because the span is
// meant to contain it, so a span that closes early is a correctness bug and not
// a cosmetic one.
func TestRenderMarkdownWidensTheUsageSpanAroundABacktickInUse(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{
		{Path: "tool", Use: "tool", Short: "the tool", Runnable: true},
		{Path: "tool scan", Use: "scan `--target` <domain>", Short: "scan things", Runnable: true},
	}}

	scan := section(t, string(d.renderMarkdown(s)), "tool scan")

	assert.Contains(t, scan, "- Usage: `` tool scan `--target` <domain> ``\n",
		"the delimiter widens and the padding keeps the value's own backticks inside the span")
	assert.NotContains(t, scan, "- Usage: `tool scan `",
		"a single-tick wrap would close at the value's backtick and push <domain> into live markdown")
}

func TestFenceWidensToContainALeadingBacktickRun(t *testing.T) {
	assert.Equal(t, "```", fence(""))
	assert.Equal(t, "```", fence("plain"))
	assert.Equal(t, "```", fence("a`b mid-line"),
		"a closing fence must begin its line, so an inline run leaves the standard three")
	assert.Equal(t, "````", fence("```\nrest"))
	assert.Equal(t, "````", fence("  ```\nrest"),
		"leading whitespace is trimmed before measuring, matching CommonMark's indent-tolerant close")
	assert.Equal(t, "`````", fence("````"))
	assert.Equal(t, "````", fence("foo\n```\nbar"))
}

func TestRenderMarkdownWidensTheExamplesFenceAroundATripleBacktickLine(t *testing.T) {
	d := newTestDocs(t)
	s := Surface{Commands: []Command{{
		Path: "tool", Use: "tool", Runnable: true, Short: "the tool",
		Example: "tool run\n```\necho injected\n```",
	}}}

	md := string(d.renderMarkdown(s))
	section := section(t, md, "tool")

	assert.Contains(t, section, "\n````bash\ntool run\n```\necho injected\n```\n````\n",
		"the delimiter widens so the example's own ``` line cannot close the block")
	assert.NotContains(t, section, "\n```bash\n",
		"a fixed three-tick fence would close on the first line of the example")
}
