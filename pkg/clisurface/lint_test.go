package clisurface

import (
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyAllowlist is the allowlist used by tests that do not exercise it.
func emptyAllowlist(t *testing.T) Allowlist {
	t.Helper()
	allow, err := newTestDocs(t).ParseAllowlist("")
	require.NoError(t, err)
	return allow
}

// tokensOf flattens issues to their offending tokens.
func tokensOf(issues []Issue) []string {
	out := make([]string, 0, len(issues))
	for i := range issues {
		out = append(out, issues[i].Token)
	}
	return out
}

func TestShellSegmentsSplitsPipelines(t *testing.T) {
	segments := shellSegments("naabu -host 10.0.0.0/24 -silent | nerva --json | brutus creds -P passwords.txt")

	require.Len(t, segments, 3)
	assert.Equal(t, []string{"naabu", "-host", "10.0.0.0/24", "-silent"}, segments[0])
	assert.Equal(t, []string{"nerva", "--json"}, segments[1])
	assert.Equal(t, []string{"brutus", "creds", "-P", "passwords.txt"}, segments[2])
}

func TestShellSegmentsKeepsQuotedValuesWhole(t *testing.T) {
	segments := shellSegments(`brutus logon --target host --exec "net user attacker P@ssw0rd /add && net localgroup administrators attacker /add"`)

	require.Len(t, segments, 1, "the && inside quotes must not split the command")
	assert.Equal(t, []string{
		"brutus", "logon", "--target", "host", "--exec",
		"net user attacker P@ssw0rd /add && net localgroup administrators attacker /add",
	}, segments[0])
}

func TestShellSegmentsHandlesPromptsCommentsAndSeparators(t *testing.T) {
	assert.Equal(t, [][]string{{"brutus", "creds"}}, shellSegments("$ brutus creds"),
		"a copied shell prompt is not argv[0]")
	assert.Equal(t, [][]string{{"brutus", "creds"}}, shellSegments("brutus creds    # test SSH, MySQL, ..."),
		"an unquoted # starts a comment")
	assert.Empty(t, shellSegments("# only a comment"))
	assert.Equal(t, [][]string{{"brutus", "creds"}, {"results.json"}}, shellSegments("brutus creds > results.json"),
		"a redirect target is its own segment, so it is never read as a flag")
	assert.Equal(t, [][]string{{"jq", "-r", `"\(.target) \(.username)"`, "findings.json"}},
		shellSegments(`jq -r '"\(.target) \(.username)"' findings.json`),
		"single quotes are literal")
}

func TestLintMarkdownOnlyChecksTheCLIsOwnInvocations(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"```bash",
		"naabu -host 10.0.0.0/24 -p 3389 -silent | nerva --json | tool scan",
		"curl -LO https://example.com/tool.tar.gz | tar -xzf -",
		"go install example.com/cmd/tool@latest",
		"sudo mv tool /usr/local/bin/",
		"jq 'select(.finding)' findings.json",
		"```",
	}, "\n")

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	assert.Empty(t, issues, "flags belonging to other tools in the pipeline must never be validated")
}

func TestLintMarkdownReportsFlagsTheCommandDoesNotHave(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"prose line",
		"```bash",
		"tool scan --target host --targt host",
		"```",
	}, "\n")

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "--targt", issues[0].Token)
	assert.Equal(t, 3, issues[0].Line, "the issue points at the line inside the fence")
	assert.Equal(t, "tool scan", issues[0].Command)
	assert.Equal(t, "--target", issues[0].Suggestion, "the nearest real flag is offered")
	assert.Contains(t, issues[0].String(), `README.md:3: --targt is not a flag of "tool scan"`,
		"the message names the file, the line, the token and the command")
	assert.Contains(t, issues[0].String(), d.Config().AllowlistPath, "the message says how to allow a deliberate mention")
}

func TestLintMarkdownReportsFlagsRejectedByTheCommand(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := "```bash\ntool guarded --timeout 30s\n```"

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1, "--timeout is inherited but the command refuses it")
	assert.Equal(t, "--timeout", issues[0].Token)
	assert.Equal(t, "tool guarded", issues[0].Command)
	assert.Contains(t, issues[0].Reason, "use --scan-timeout", "the command's own error explains the rejection")
	assert.Empty(t, issues[0].Suggestion, "the rejection message is the guidance; an edit-distance guess would add noise")
}

func TestLintMarkdownAcceptsInheritedAndHiddenFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := "```bash\ntool scan --target host --timeout 5s --json\ntool guarded --scan-timeout 15s --json\n```"

	assert.Empty(t, d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t)),
		"a flag inherited from the root is usable unless the command rejects it")
}

func TestLintMarkdownJoinsLineContinuations(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"```bash",
		"naabu -host 10.0.0.0/24 -silent | \\",
		"  nerva --json | \\",
		"  tool scan --nope",
		"```",
	}, "\n")

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1, "the continued pipeline is one logical command line")
	assert.Equal(t, "--nope", issues[0].Token)
	assert.Equal(t, 2, issues[0].Line, "a continued line is reported at the line it starts on")
}

func TestLintMarkdownChecksShorthandFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\ntool scan -t host -j\n```", emptyAllowlist(t)))

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool scan -Z host\n```", emptyAllowlist(t))
	require.Len(t, issues, 1)
	assert.Equal(t, "-Z", issues[0].Token)
	assert.Contains(t, issues[0].Reason, "is not a shorthand flag of")
}

func TestLintMarkdownIgnoresValuesThatLookLikeFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := "```bash\ntool scan --target - -t -\n```"

	assert.Empty(t, d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t)),
		"a bare - is stdin, not a flag")
}

func TestLintMarkdownResolvesSubcommandsAndAliases(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\ntool sc --target host\ntool group leaf --only-here x\n```", emptyAllowlist(t)),
		"aliases and nested paths must resolve")

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool group leef --only-here x\n```", emptyAllowlist(t))
	require.Len(t, issues, 2, "the unknown subcommand and the flag it cannot carry are both reported")
	assert.Equal(t, "leef", issues[0].Token)
	assert.Contains(t, issues[0].Reason, "is not a subcommand of")
	assert.Equal(t, "leaf", issues[0].Suggestion)
}

// TestLintMarkdownResolvesAConsumerDeclaredCompletionCommand is the downstream
// cost of dropping a root-level command from the surface by name. The linter
// resolves every documented invocation against the surface, so a command missing
// from it turns each documented use into an unknown-subcommand issue and each of
// its flags into an unknown flag -- the gate reporting drift against a command
// that is not actually drifting.
func TestLintMarkdownResolvesAConsumerDeclaredCompletionCommand(t *testing.T) {
	d := newTestDocs(t)
	root := newTestTree()
	shell := &cobra.Command{Use: "completion", Short: "print our own shell integration", RunE: func(*cobra.Command, []string) error { return nil }}
	shell.Flags().String("shell", "bash", "which shell to emit the integration for")
	root.AddCommand(shell)
	s := Walk(root)

	assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\ntool completion --shell zsh\n```", emptyAllowlist(t)),
		"a command the consumer declared must resolve, and its own flags with it")
}

func TestLintMarkdownTreatsPositionalArgumentsAsValues(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\ntool scan somehost:22\n```", emptyAllowlist(t)),
		"a leaf command's positional argument is not a subcommand")
}

func TestLintMarkdownChecksBacktickedFlagsInProse(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"Route traffic through `--timeout 5s` or use `--mode cautious|default|aggressive`.",
		"Unbackticked --alsogone is ignored because prose says things loosely.",
		"```bash",
		"tool scan --target host",
		"```",
	}, "\n")

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "--mode", issues[0].Token)
	assert.Equal(t, 1, issues[0].Line)
	assert.Empty(t, issues[0].Command, "prose is checked against the whole surface, not one command")
	assert.Contains(t, issues[0].Reason, "is not a flag of any command")
}

func TestLintMarkdownIgnoresProseInsideFencesAndFencesInsideProse(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"~~~",
		"tool scan --gone",
		"~~~",
		"`--gone` in prose is reported once more",
	}, "\n")

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 2, "a tilde fence is a fence, and prose after it is prose")
	assert.Equal(t, 2, issues[0].Line)
	assert.Equal(t, "tool scan", issues[0].Command)
	assert.Equal(t, 4, issues[1].Line)
	assert.Empty(t, issues[1].Command)
}

func TestLintGoCommentsReportsRenamedFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	src := []byte(`package demo

// runInteractive handles the --scan-timeout and --sticky-keys-exec modes.
func runInteractive() {}

// ---------------------------------------------------------------------------
// A rule comment and a dash--dash word must not look like flags.
`)

	issues, err := d.lintGoComments(s, "cmd/demo/demo.go", src, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 1)
	assert.Equal(t, "--sticky-keys-exec", issues[0].Token)
	assert.Equal(t, "cmd/demo/demo.go", issues[0].File)
	assert.Equal(t, 3, issues[0].Line)
	assert.Contains(t, issues[0].Reason, "is named in a comment")
}

func TestLintGoCommentsIgnoresStringLiteralsAndCode(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	src := []byte(`package demo

func run() string { return "--not-a-real-flag" }
`)

	issues, err := d.lintGoComments(s, "cmd/demo/demo.go", src, emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues, "only comments are checked; string literals are out of scope")
}

func TestLintGoCommentsFailsOnUnparseableSource(t *testing.T) {
	d := newTestDocs(t)

	_, err := d.lintGoComments(Walk(newTestTree()), "cmd/demo/demo.go", []byte("not go at all"), emptyAllowlist(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing cmd/demo/demo.go")
}

func TestAllowlistSuppressesDeliberateMentions(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	allow, err := d.ParseAllowlist(strings.Join([]string{
		"# deliberate historical references",
		"--sticky-keys-exec  # renamed to --exec in v1.9; the rename note has to name the old flag",
		"",
		"-Z # nmap's -Z, quoted in a pipeline example",
	}, "\n"))
	require.NoError(t, err)

	assert.Equal(t, []string{"--sticky-keys-exec", "-Z"}, allow.Entries())
	assert.True(t, allow.Allows("--sticky-keys-exec"))
	assert.False(t, allow.Allows("--something-else"))

	doc := "`--sticky-keys-exec` was renamed.\n```bash\ntool scan -Z --sticky-keys-exec\n```"
	assert.Empty(t, d.LintMarkdown(s, "README.md", doc, allow))
	assert.NotEmpty(t, d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t)),
		"without the allowlist the same document is reported")
}

func TestParseAllowlistRequiresAReason(t *testing.T) {
	d := newTestDocs(t)

	_, err := d.ParseAllowlist("--orphan\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a '# reason'")

	_, err = d.ParseAllowlist("--orphan #   \n")
	require.Error(t, err)

	_, err = d.ParseAllowlist("orphan # missing dashes\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must start with '-'")
}

func TestIssueInAGeneratedFilePointsAtRegeneration(t *testing.T) {
	d := newTestDocs(t)

	generated := d.stamp(Issue{File: d.Config().MarkdownPath, Line: 12, Token: "--gone", Reason: "is not a flag of any command in the CLI"})
	assert.Equal(t,
		"docs/CLI.md:12: --gone is not a flag of any command in the CLI. docs/CLI.md is generated: regenerate it with 'make cli-docs' rather than editing it",
		generated.String(),
		"a stale generated file must not be advertised as something to hand-edit or allowlist")

	for _, file := range []string{"CONTRIBUTING.md", d.Config().READMEPath} {
		handWritten := d.stamp(Issue{File: file, Line: 12, Token: "--gone", Reason: "is not a flag of any command in the CLI"})
		assert.Contains(t, handWritten.String(), d.Config().AllowlistPath,
			"%s still offers the allowlist escape hatch: only two regions of README.md are generated", file)
		assert.NotContains(t, handWritten.String(), testRegenerateCommand, "%s", file)
	}
}

// TestIssueInAGeneratedFileIsRecognisedThroughAnUncleanedPath is the defect that
// cleaning the scalar path fields fixes. The file on an issue comes from the
// documentation walk and so is cleaned, while the path it is compared against
// came from the Config -- so a caller who wrote "./docs/CLI.md" made the two
// unequal for the same file, and every lint hit inside the generated reference
// was advertised as prose to hand-edit or allowlist, which is precisely what the
// message it should have printed tells the reader not to do.
func TestIssueInAGeneratedFileIsRecognisedThroughAnUncleanedPath(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.MarkdownPath = "./docs/CLI.md" })

	issue := d.stamp(Issue{File: "docs/CLI.md", Line: 12, Token: "--gone", Reason: "is not a flag of any command in the CLI"})

	assert.Equal(t,
		"docs/CLI.md:12: --gone is not a flag of any command in the CLI. docs/CLI.md is generated: regenerate it with 'make cli-docs' rather than editing it",
		issue.String(),
		"the spelling of MarkdownPath must not decide whether a generated file is recognised as one")
}

func TestLintReportNumbersEveryIssue(t *testing.T) {
	report := LintReport([]Issue{
		{File: "README.md", Line: 7, Token: "--gone", Reason: "is not a flag of any command in the CLI"},
		{File: "docs/CLI.md", Line: 9, Token: "--also-gone", Reason: "is not a flag of any command in the CLI"},
	}, LintScope{MarkdownFiles: []string{"README.md", "docs/CLI.md"}})

	assert.Contains(t, report, "references 2 CLI flag(s)")
	assert.Contains(t, report, "1. README.md:7: --gone")
	assert.Contains(t, report, "2. docs/CLI.md:9: --also-gone")
}

func TestNearestOnlySuggestsPlausibleMatches(t *testing.T) {
	assert.Equal(t, "--target", nearest("targt", []string{"target", "timeout"}))
	assert.Empty(t, nearest("wildly-different", []string{"target", "timeout"}),
		"a distant token gets no suggestion rather than a misleading one")
}

func TestTokensOfIssuesAreStable(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := "```bash\ntool scan --aaa --bbb\n```"
	assert.Equal(t, []string{"--aaa", "--bbb"}, tokensOf(d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))))
}

// TestLintMarkdownResolvesSubcommandsAcrossGlobalFlags pins the fix for the
// linter's worst failure mode: a global flag written before the subcommand used
// to stop subcommand resolution, so every later flag was validated against the
// root and a perfectly valid example was reported as drift.
func TestLintMarkdownResolvesSubcommandsAcrossGlobalFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	for _, line := range []string{
		"tool --json scan --target host",             // boolean global first
		"tool --timeout 5s scan --target host",       // value-taking global first
		"tool --timeout=5s group leaf --only-here x", // attached value, nested path
		"tool -j scan --target host",                 // boolean shorthand first
		"tool -j --timeout 5s sc --target host",      // several globals, then an alias
	} {
		assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\n"+line+"\n```", emptyAllowlist(t)),
			"%q is a valid invocation: cobra accepts a global flag before the subcommand", line)
	}
}

// TestLintMarkdownCatchesABadSubcommandAfterAGlobalFlag is the other half of the
// same fix. Resolution used to stop at the first flag, which silently swallowed
// a misspelled subcommand written after one.
func TestLintMarkdownCatchesABadSubcommandAfterAGlobalFlag(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool --json groop leaf\n```", emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "groop", issues[0].Token)
	assert.Equal(t, "tool", issues[0].Command)
	assert.Contains(t, issues[0].Reason, "is not a subcommand of")
	assert.Equal(t, "group", issues[0].Suggestion)
}

// TestLintMarkdownDoesNotReadFlagValuesAsFlags pins the second false-positive
// class: a value that pflag reads as one token used to be scanned as a cluster
// of shorthands, so "-thost" became -t plus five invented flags.
func TestLintMarkdownDoesNotReadFlagValuesAsFlags(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	for _, line := range []string{
		"tool scan -thost",                  // value attached to the shorthand
		"tool scan -t=host",                 // value attached with =
		"tool scan -t host",                 // value as the next argument
		"tool scan -jt host",                // boolean clustered before a value-taking flag
		"tool scan --target -weird-looking", // a value that starts with a dash
	} {
		assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\n"+line+"\n```", emptyAllowlist(t)),
			"%q: the flag's value must not be scanned as flags", line)
	}
}

// TestLintMarkdownStopsAtTheDashDashSeparator checks that a token after "--" is
// a positional argument, however much it looks like a flag.
func TestLintMarkdownStopsAtTheDashDashSeparator(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\ntool scan -- --not-a-flag-here\n```", emptyAllowlist(t)),
		"pflag stops parsing flags at a bare --")
}

// TestLintMarkdownStillCatchesFlagsAfterAResolvedSubcommand guards against the
// resolution fix loosening the check: the flags of a correctly resolved deep
// command must still be validated against that command.
func TestLintMarkdownStillCatchesFlagsAfterAResolvedSubcommand(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool --json group leaf --only-here x --gone y\n```", emptyAllowlist(t))

	require.Len(t, issues, 1)
	assert.Equal(t, "--gone", issues[0].Token)
	assert.Equal(t, "tool group leaf", issues[0].Command,
		"the flag is checked against the command the global flag did not hide")
}

// TestSubcommandIssueDoesNotOfferTheFlagAllowlist checks the advice matches the
// token. The allowlist holds flag tokens only, so pointing a misspelled
// subcommand at it would send the reader to write an entry ParseAllowlist
// rejects.
func TestSubcommandIssueDoesNotOfferTheFlagAllowlist(t *testing.T) {
	d := newTestDocs(t)
	issue := d.stamp(Issue{
		File: "README.md", Line: 3, Token: "groop", Command: "tool",
		Reason: "is not a subcommand of", Suggestion: "group", Subcommand: true,
	})

	rendered := issue.String()
	assert.Contains(t, rendered, `README.md:3: groop is not a subcommand of "tool"`)
	assert.Contains(t, rendered, "nearest subcommand: group")
	assert.NotContains(t, rendered, "add groop to", "the allowlist parser rejects an entry that is not a flag")

	_, err := d.ParseAllowlist("groop # what the old message told the reader to write\n")
	require.Error(t, err, "the advice the message used to give was not even valid")
}

// TestLintMarkdownTreatsHelpAsBoolean checks that --help and -h do not swallow
// the token after them: both are boolean, and cobra registers them on every
// command without them appearing in the surface.
func TestLintMarkdownTreatsHelpAsBoolean(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool --help groop\ntool -h groop\n```", emptyAllowlist(t))

	require.Len(t, issues, 2, "the subcommand after --help/-h is still resolved and still checked")
	for i := range issues {
		assert.Equal(t, "groop", issues[i].Token)
		assert.Equal(t, "group", issues[i].Suggestion)
	}
}

// TestLintMarkdownJudgesEveryFlagAgainstTheResolvedCommand pins the order of the
// two stages. cobra dispatches to the resolved command and parses the whole argv
// against that command's flag set, so writing a flag before the subcommand does
// not excuse it: a flag the command rejects, and a flag local to the root, both
// fail at runtime wherever they appear.
func TestLintMarkdownJudgesEveryFlagAgainstTheResolvedCommand(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())

	t.Run("a rejected inherited flag is caught before the subcommand too", func(t *testing.T) {
		for _, line := range []string{
			"tool guarded --timeout 30s",
			"tool --timeout 30s guarded",
			"tool --timeout=30s guarded --scan-timeout 5s",
		} {
			issues := d.LintMarkdown(s, "README.md", "```bash\n"+line+"\n```", emptyAllowlist(t))
			require.Len(t, issues, 1, "%q: guarded refuses --timeout wherever it is written", line)
			assert.Equal(t, "--timeout", issues[0].Token)
			assert.Equal(t, "tool guarded", issues[0].Command,
				"the flag is judged against the command cobra would dispatch to")
			assert.Contains(t, issues[0].Reason, "use --scan-timeout")
		}
	})

	t.Run("a root-local flag is not usable once a subcommand is named", func(t *testing.T) {
		assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\ntool --version\n```", emptyAllowlist(t)),
			"--version is a flag of the root itself")

		issues := d.LintMarkdown(s, "README.md", "```bash\ntool --version scan\n```", emptyAllowlist(t))
		require.Len(t, issues, 1, "--version is local to the root, not persistent, so scan does not accept it")
		assert.Equal(t, "--version", issues[0].Token)
		assert.Equal(t, "tool scan", issues[0].Command)
	})

	t.Run("a persistent flag stays usable everywhere", func(t *testing.T) {
		for _, line := range []string{
			"tool --json scan --target host",
			"tool scan --json --target host",
			"tool --json group leaf --only-here x",
		} {
			assert.Empty(t, d.LintMarkdown(s, "README.md", "```bash\n"+line+"\n```", emptyAllowlist(t)), "%q", line)
		}
	})
}

// TestLintMarkdownKeepsExplicitlyEmptyArguments pins the quoted-empty-token fix. Dropping
// an explicit "" shifts every later token: the flag after it became its value, and an
// invalid flag went unreported.
func TestLintMarkdownKeepsExplicitlyEmptyArguments(t *testing.T) {
	d := newTestDocs(t)

	assert.Equal(t, [][]string{{"tool", "scan", "--target", "", "--gone"}},
		shellSegments(`tool scan --target "" --gone`),
		"an explicitly quoted empty argument is still an argument")

	issues := d.LintMarkdown(Walk(newTestTree()), "README.md",
		"```bash\ntool group leaf --only-here \"\" --gone\n```", emptyAllowlist(t))

	require.Len(t, issues, 1, "--gone must not be swallowed as the value of --only-here")
	assert.Equal(t, "--gone", issues[0].Token)
}

// TestLintMarkdownRespectsFenceLength pins the fence run length. A block opened with
// four backticks may contain a three-backtick line as content, and closing on it early
// inverts the fence state for the whole rest of the document -- so prose afterwards is
// read as shell and never checked as prose.
func TestLintMarkdownRespectsFenceLength(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	doc := strings.Join([]string{
		"````text", // opens a four-backtick block
		"```",      // content, not a close: shorter than the opener
		"````",     // the real close
		"",
		"Prose mentioning `--gone-from-prose`.",
	}, "\n")

	issues := d.LintMarkdown(s, "README.md", doc, emptyAllowlist(t))

	require.Len(t, issues, 1, "the trailing line is prose and must be checked as prose:\n%v", tokensOf(issues))
	assert.Equal(t, "--gone-from-prose", issues[0].Token)
	assert.Empty(t, issues[0].Command, "a prose hit is checked against the whole surface, not one command")
	assert.Equal(t, 5, issues[0].Line)
}

// TestLintGoCommentsIgnoresSentencePunctuation pins the shared token cleanup. A Go
// comment is not delimited the way a backticked prose span is, so a flag ending a
// sentence arrives with the period attached and would be reported as nonexistent.
func TestLintGoCommentsIgnoresSentencePunctuation(t *testing.T) {
	d := newTestDocs(t)
	s := Walk(newTestTree())
	src := []byte("package demo\n\n// Pass --timeout. Or use --json.\nconst A = 1\n")

	issues, err := d.lintGoComments(s, "cmd/demo/demo.go", src, emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues, "a trailing period is punctuation, not part of the flag")

	issues, err = d.lintGoComments(s, "cmd/demo/demo.go",
		[]byte("package demo\n\n// Pass --nonexistent.\nconst A = 1\n"), emptyAllowlist(t))
	require.NoError(t, err)
	require.Len(t, issues, 1, "a real unknown flag is still reported")
	assert.Equal(t, "--nonexistent", issues[0].Token, "and reported without the punctuation")
}

// TestLintMarkdownNamesTheConfiguredAllowlistPath is one half of the Config seam's
// proof: the advice a real issue carries has to name the allowlist the receiver was
// configured with, not the default the ported source hard-coded. A non-default path
// is the only value that can tell the two apart.
func TestLintMarkdownNamesTheConfiguredAllowlistPath(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.AllowlistPath = "etc/allowed-flags.txt" })
	s := Walk(newTestTree())

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool scan --gone\n```", emptyAllowlist(t))

	require.Len(t, issues, 1)
	rendered := issues[0].String()
	assert.Contains(t, rendered, "add --gone to etc/allowed-flags.txt with a '#' reason",
		"the issue names the configured allowlist")
	assert.NotContains(t, rendered, "docs/cli-surface-allow.txt", "and not the default it replaced")
}

// TestZeroIssueRendersWithoutAnyConfiguredPath pins the documented cost of stamping.
// An Issue a caller builds itself carries no resolved Config, and String has to stay
// safe on it: no panic, and -- because it cannot name an artifact it was never told
// about -- no claim that the file is generated.
func TestZeroIssueRendersWithoutAnyConfiguredPath(t *testing.T) {
	var zero Issue

	rendered := zero.String()

	assert.NotPanics(t, func() { _ = zero.String() })
	assert.Equal(t, ":0:  ", rendered[:len(":0:  ")], "the fields it does have still render")
	assert.NotContains(t, rendered, "is generated", "an unstamped issue must not claim a file is generated")
}

// TestLintReportStatesAScopeThatMatchedNothing is the visible-zero check. A walk root
// that is missing, or is a symlink, lints no files at all, and a report that says only
// that there were no issues reads exactly like a clean repository. The scope line is
// what makes the difference legible.
func TestLintReportStatesAScopeThatMatchedNothing(t *testing.T) {
	report := LintReport(nil, LintScope{})

	assert.Contains(t, report, "Linted 0 markdown file(s) [none] and 0 Go file(s) under 0 Go dir(s) [none]",
		"an empty scope reports zeros rather than saying nothing")
	assert.Contains(t, report, "with 0 token(s) allowlisted.")
	assert.True(t, strings.HasSuffix(report, "allowlisted."), "the scope line is the last line of the report")
}

// TestLintReportCountsTheScopeItWasGiven is the other half: a scope that did match
// files reports what it reached, including the allowlist size, which is otherwise
// invisible because a suppressed token leaves no issue behind.
func TestLintReportCountsTheScopeItWasGiven(t *testing.T) {
	d := newTestDocs(t)
	allow, err := d.ParseAllowlist("--sticky-keys-exec # renamed; the note has to name the old flag\n")
	require.NoError(t, err)

	report := LintReport(nil, LintScope{
		MarkdownFiles: []string{"README.md", "docs/CLI.md"},
		GoDirs:        []string{"cmd", "internal"},
		GoFiles:       []string{"cmd/tool/main.go", "internal/scan/scan.go", "internal/scan/scan_test.go"},
		Allowlist:     allow,
	})

	assert.Contains(t, report,
		"Linted 2 markdown file(s) [README.md, docs/CLI.md] and 3 Go file(s) under 2 Go dir(s) [cmd, internal], with 1 token(s) allowlisted.")
}

// --- positional arguments vs. misspelled subcommands ------------------------

// newPositionalSurface fills out the 2x2 of Runnable x hasArgSketch among
// commands that HAVE children, which is the only quadrant reportsBogusSubcommand
// looks at. Each cell is a real cobra shape:
//
//	titus github  runnable, sketches [owner/repo]  -- dispatches and takes an arg
//	titus notes   runnable, no sketch              -- the common root-like shape
//	titus report  not runnable, sketches <format>  -- a grouping parent whose Use
//	                                                  mis-advertises an argument
//	titus group   not runnable, no sketch          -- the classic grouping parent
//
// It is hand-built because a cobra tree cannot express "not runnable yet
// sketches an argument" without also giving the command a RunE.
func newPositionalSurface() Surface {
	return Surface{Commands: []Command{
		{Path: "titus", Use: "titus", Short: "the tool", Runnable: true},

		{Path: "titus github", Use: "github [owner/repo]", Short: "scan one repository", Runnable: true},
		{Path: "titus github targets", Use: "targets", Short: "list discovered targets", Runnable: true},

		{Path: "titus notes", Use: "notes", Short: "manage notes", Runnable: true},
		{Path: "titus notes list", Use: "list", Short: "list notes", Runnable: true},

		{Path: "titus report", Use: "report <format>", Short: "reporting commands"},
		{Path: "titus report csv", Use: "csv", Short: "emit csv", Runnable: true},

		{Path: "titus group", Use: "group", Short: "a grouping parent"},
		{Path: "titus group leaf", Use: "leaf", Short: "a leaf", Runnable: true},
	}}
}

// TestLintMarkdownAcceptsAPositionalOnAParentThatTakesOne is the false positive
// that was measured on titus. Its README documents "titus github owner/repo",
// which is correct: the command dispatches to subcommands AND takes an
// owner/repo argument of its own. The linter reported the argument as a
// misspelled subcommand, and there was no escape -- ParseAllowlist rejects any
// entry that does not start with "-" -- so the only way to clear the report was
// to rewrite a true documentation line into a false one.
func TestLintMarkdownAcceptsAPositionalOnAParentThatTakesOne(t *testing.T) {
	t.Parallel()

	d := newTestDocs(t)
	s := newPositionalSurface()

	github, ok := s.Command("titus github")
	require.True(t, ok)
	require.True(t, github.Runnable, "it has a RunE of its own")
	require.Equal(t, "github [owner/repo]", github.Use, "and its Use declares the argument")
	require.NotEmpty(t, s.Children("titus github"), "and it dispatches to children too: that is the shape that misfired")

	issues := d.LintMarkdown(s, "README.md", "```bash\ntitus github owner/repo\n```", emptyAllowlist(t))
	assert.Empty(t, issues, "a documented positional on a command that declares one is not a misspelled subcommand: %v", tokensOf(issues))

	_, err := d.ParseAllowlist("owner/repo\n")
	require.Error(t, err, "and the allowlist could never have suppressed it: it accepts flag tokens only")
}

// TestLintMarkdownReportsABogusSubcommandOnlyWhenTheParentTakesNoArgument walks
// every cell of the Runnable x hasArgSketch table. Both conjuncts of
// takesPositional are load-bearing and each has a cell that fails alone if it is
// dropped: widening to "Runnable" alone breaks the notes row, and narrowing to
// "hasArgSketch" alone breaks the report row.
func TestLintMarkdownReportsABogusSubcommandOnlyWhenTheParentTakesNoArgument(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		command        string
		line           string
		wantToken      string // "" means the positional must be accepted in silence
		wantSuggestion string
	}{
		{
			name:    "runnable and sketches an argument: the positional is that argument",
			command: "titus github",
			line:    "titus github owner/repo",
		},
		{
			name:      "runnable but sketches nothing: a positional is still a typo",
			command:   "titus notes",
			line:      "titus notes mynote",
			wantToken: "mynote",
		},
		{
			name:           "sketches an argument but is not runnable: still a typo",
			command:        "titus report",
			line:           "titus report cvs",
			wantToken:      "cvs",
			wantSuggestion: "csv",
		},
		{
			name:           "neither runnable nor sketching: the classic grouping parent",
			command:        "titus group",
			line:           "titus group leef",
			wantToken:      "leef",
			wantSuggestion: "leaf",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newTestDocs(t)
			s := newPositionalSurface()

			cmd, ok := s.Command(tc.command)
			require.True(t, ok)
			require.NotEmpty(t, s.Children(cmd.Path), "every cell of this table needs a parent that has children")

			issues := d.LintMarkdown(s, "README.md", "```bash\n"+tc.line+"\n```", emptyAllowlist(t))

			if tc.wantToken == "" {
				assert.Empty(t, issues, "unexpected findings: %v", tokensOf(issues))
				return
			}

			require.Len(t, issues, 1, "findings: %v", tokensOf(issues))
			assert.Equal(t, tc.wantToken, issues[0].Token)
			assert.Equal(t, tc.command, issues[0].Command, "the finding is blamed on the resolved parent")
			assert.True(t, issues[0].Subcommand, "and it is a subcommand finding, so no flag allowlist is offered")
			assert.Contains(t, issues[0].Reason, "is not a subcommand of")
			assert.Equal(t, tc.wantSuggestion, issues[0].Suggestion,
				"the nearest-subcommand suggestion is the finding's most valuable output and must survive the fix")
		})
	}
}

// TestLintMarkdownStillCatchesATypoUnderARunnableRoot is the exact regression a
// first attempt at this fix introduced: keying on "has children && !Runnable"
// looked right and was not. A root with a RunE and subcommands is the
// overwhelmingly common cobra shape -- the fixture root in surface_test.go is
// one -- so Runnable alone silently switched off top-level typo detection for
// nearly every CLI, which is the one place a documentation typo is most likely
// and where the suggestion pays off most.
//
// Runnable is necessary but not sufficient: the command must also declare an
// argument before a positional is read as one.
func TestLintMarkdownStillCatchesATypoUnderARunnableRoot(t *testing.T) {
	t.Parallel()

	d := newTestDocs(t)
	s := Walk(newTestTree())

	root, ok := s.Command(s.Root())
	require.True(t, ok)
	require.True(t, root.Runnable, "the fixture root runs")
	require.NotEmpty(t, s.Children(root.Path), "and dispatches: the shape that broke the first attempt")
	require.False(t, hasArgSketch(root.Use), "but it declares no argument, so a positional is not one")

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool groop\n```", emptyAllowlist(t))

	require.Len(t, issues, 1, "findings: %v", tokensOf(issues))
	assert.Equal(t, "groop", issues[0].Token)
	assert.Equal(t, "tool", issues[0].Command)
	assert.Equal(t, "group", issues[0].Suggestion)
}

func TestLintMarkdownReportsATypoUnderCobrasCommandPlaceholder(t *testing.T) {
	t.Parallel()

	d := newTestDocs(t)
	s := Surface{Commands: []Command{
		{Path: "tool", Use: "tool", Short: "the tool", Runnable: true},
		{Path: "tool config", Use: "config [command]", Short: "configure", Runnable: true},
		{Path: "tool config show", Use: "show", Short: "print it", Runnable: true},
	}}

	cfg, ok := s.Command("tool config")
	require.True(t, ok)
	require.True(t, cfg.Runnable)
	require.False(t, hasArgSketch(cfg.Use), "cobra's [command] placeholder is not an argument sketch")
	require.NotEmpty(t, s.Children(cfg.Path))

	issues := d.LintMarkdown(s, "README.md", "```bash\ntool config shwo\n```", emptyAllowlist(t))

	require.Len(t, issues, 1, "findings: %v", tokensOf(issues))
	assert.Equal(t, "shwo", issues[0].Token)
	assert.Equal(t, "tool config", issues[0].Command)
	assert.Equal(t, "show", issues[0].Suggestion)
	assert.True(t, issues[0].Subcommand)
}

// TestHasArgSketchRecognizesBothArgumentConventions covers the shapes cobra Use
// strings actually take. Neither convention is dominant in this codebase --
// titus writes "[owner/repo]" and umber writes "<name>" -- and the two tokens
// cobra itself contributes ("[flags]" and a bare shorthand) must not read as
// arguments, or every command with a flag would accept any positional.
func TestHasArgSketchRecognizesBothArgumentConventions(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		use  string
		want bool
	}{
		{use: "github [owner/repo]", want: true},
		{use: "scan <domain>", want: true},
		{use: "cp <src> <dst>", want: true},
		{use: "scan [flags] <domain>", want: true},
		{use: "scan domain", want: true},

		{use: "", want: false},
		{use: "   ", want: false},
		{use: "scan", want: false},
		{use: "scan [flags]", want: false},
		{use: "config [command]", want: false},
		{use: "config [COMMAND]", want: false},
		{use: "help [command]", want: false},
		{use: "group <command>", want: false},
		{use: "group [subcommand]", want: false},
		{use: "group <subcommand>", want: false},
		{use: "scan -j", want: false},
		{use: "scan --json", want: false},
		{use: "scan [flags] --json", want: false},
		{use: "config [command] <file>", want: true},
	} {
		t.Run(strconv.Quote(tc.use), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, hasArgSketch(tc.use))
		})
	}
}

// TestLintMarkdownStopsResolvingAtTheFirstArgument pins the unconditional
// "resolving = false" on every non-child path out of the arm. Once a token has
// been read as an argument rather than a subcommand, later bare words are that
// command's remaining arguments -- they must not advance the resolved command,
// or every flag after them is judged against the wrong one.
func TestLintMarkdownStopsResolvingAtTheFirstArgument(t *testing.T) {
	t.Parallel()

	t.Run("after an accepted argument", func(t *testing.T) {
		t.Parallel()

		d := newTestDocs(t)
		s := newPositionalSurface()

		issues := d.LintMarkdown(s, "README.md",
			"```bash\ntitus github owner/repo targets --gone\n```", emptyAllowlist(t))

		require.Len(t, issues, 1,
			"owner/repo is accepted, and the child-named token after it is a second argument: %v", tokensOf(issues))
		assert.Equal(t, "--gone", issues[0].Token)
		assert.Equal(t, "titus github", issues[0].Command,
			"with resolving left on, targets would advance the command and --gone would be blamed on titus github targets")
	})

	t.Run("after a reported typo", func(t *testing.T) {
		t.Parallel()

		d := newTestDocs(t)
		s := Walk(newTestTree())

		issues := d.LintMarkdown(s, "README.md",
			"```bash\ntool somearg group --gone\n```", emptyAllowlist(t))

		require.Len(t, issues, 2, "findings: %v", tokensOf(issues))
		assert.Equal(t, "somearg", issues[0].Token)
		assert.Equal(t, "tool", issues[0].Command)
		assert.Equal(t, "--gone", issues[1].Token)
		assert.Equal(t, "tool", issues[1].Command,
			"reporting a token does not consume it as a subcommand either: the flag is still judged against tool")
	})
}

// TestLintMarkdownKnownLimitationTypoUnderAnArgumentTakingParent records a real
// cost of this fix rather than an accident. Under a parent that both runs and
// declares an argument, a genuine subcommand typo is now indistinguishable from
// that argument and is accepted in silence.
//
// The trade is deliberate and asymmetric in the right direction: a missed typo
// leaves documentation that a reader can still follow, while the false positive
// it replaces pushed porters into rewriting correct documentation into incorrect
// documentation. Narrowing it would need cobra's Args validator in the surface,
// which surface.go cannot gain without invalidating every consumer's committed
// golden.
func TestLintMarkdownKnownLimitationTypoUnderAnArgumentTakingParent(t *testing.T) {
	t.Parallel()

	d := newTestDocs(t)
	s := newPositionalSurface()

	require.NotEmpty(t, s.Children("titus github"), "targets really is a subcommand, so tagets really is a typo")

	issues := d.LintMarkdown(s, "README.md", "```bash\ntitus github tagets\n```", emptyAllowlist(t))
	assert.Empty(t, issues,
		"known limitation: indistinguishable from the [owner/repo] argument the command declares: %v", tokensOf(issues))
}

// TestLintMarkdownKnownLimitationUndeclaredPositionalIsStillReported records the
// other half of the trade. The fix reads the Use string, so a command that
// really takes a positional but does not sketch it there is still reported --
// the false positive survives for exactly those commands.
//
// This one has a cheap fix available to the porter, and that is why it is
// acceptable: adding the argument to Use is a one-line change that improves
// "--help" at the same time. Widening the predicate to drop the sketch
// requirement is what must not happen, and the notes row of the 2x2 above fails
// if it does.
func TestLintMarkdownKnownLimitationUndeclaredPositionalIsStillReported(t *testing.T) {
	t.Parallel()

	d := newTestDocs(t)
	s := newPositionalSurface()

	notes, ok := s.Command("titus notes")
	require.True(t, ok)
	require.True(t, notes.Runnable)
	require.False(t, hasArgSketch(notes.Use), "the command takes a note name, but its Use never says so")

	issues := d.LintMarkdown(s, "README.md", "```bash\ntitus notes mynote\n```", emptyAllowlist(t))

	require.Len(t, issues, 1, "known limitation: an undeclared positional still reads as a typo: %v", tokensOf(issues))
	assert.Equal(t, "mynote", issues[0].Token)
	assert.Empty(t, issues[0].Suggestion, "with no near-enough child name, the finding carries no suggestion")
}
