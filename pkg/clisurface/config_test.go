package clisurface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRegenerateCommand is the one Config field with no default, fixed for the
// whole suite so every failure message a test inspects names the same command.
const testRegenerateCommand = "make cli-docs"

// newTestDocs builds a *Docs in one line: the required RegenerateCommand is
// filled in, each mod adjusts the Config before construction, and a rejected
// configuration fails the test instead of returning a nil receiver. Every
// ported suite whose subject became a *Docs method gets its receiver from here.
func newTestDocs(t *testing.T, mods ...func(*Config)) *Docs {
	t.Helper()

	cfg := Config{RegenerateCommand: testRegenerateCommand}
	for _, mod := range mods {
		mod(&cfg)
	}

	d, err := New(cfg)
	require.NoError(t, err, "newTestDocs: New must accept the test configuration")
	require.NotNil(t, d)
	return d
}

// newTestDocsError is the message New rejects cfg with, and it fails the test if
// New accepted it instead.
func newTestDocsError(t *testing.T, cfg Config) string {
	t.Helper()

	d, err := New(cfg)
	assert.Nil(t, d, "a rejected configuration must not yield a receiver")
	require.Error(t, err)
	return err.Error()
}

func TestNew_ResolvesEveryDefault(t *testing.T) {
	d := newTestDocs(t)
	cfg := d.Config()

	assert.Equal(t, testRegenerateCommand, cfg.RegenerateCommand)
	assert.Equal(t, "docs/cli-surface.json", cfg.JSONPath)
	assert.Equal(t, "docs/CLI.md", cfg.MarkdownPath)
	assert.Equal(t, "README.md", cfg.READMEPath)
	assert.Equal(t, "docs/cli-surface-allow.txt", cfg.AllowlistPath)
	assert.Equal(t, "docs", cfg.DocsWalkRoot)
	assert.Equal(t, []string{"README.md"}, cfg.LintedMarkdown)
	assert.Equal(t, []string{"cmd", "internal", "pkg"}, cfg.LintedGoDirs)
	assert.Equal(t, "cli-subcommands", cfg.SubcommandsRegion)
	assert.Equal(t, "cli-aliases", cfg.AliasesRegion)
}

func TestNew_RequiresRegenerateCommand(t *testing.T) {
	msg := newTestDocsError(t, Config{})

	assert.Contains(t, msg, "Config.RegenerateCommand is required")
}

func TestNew_RejectsWhitespaceOnlyRegenerateCommand(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: "  "})

	assert.Contains(t, msg, "Config.RegenerateCommand is required")
}

func TestNew_RejectsAnAbsolutePathField(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, JSONPath: "/etc/passwd"})

	assert.Contains(t, msg, "Config.JSONPath")
	assert.Contains(t, msg, "repository-relative")
}

func TestNew_RejectsAParentTraversalPathField(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, JSONPath: "../outside.json"})

	assert.Contains(t, msg, "Config.JSONPath")
	assert.Contains(t, msg, "..")
}

func TestNew_JoinsSimultaneousViolations(t *testing.T) {
	msg := newTestDocsError(t, Config{
		RegenerateCommand: testRegenerateCommand,
		JSONPath:          "/etc/passwd",
		MarkdownPath:      "../outside.md",
	})

	assert.Contains(t, msg, "Config.JSONPath", "both violations must be reported by one error")
	assert.Contains(t, msg, "Config.MarkdownPath")
}

func TestNew_DocsWalkRootMovesTheThreeDerivedPaths(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.DocsWalkRoot = "documentation" })
	cfg := d.Config()

	assert.Equal(t, "documentation/cli-surface.json", cfg.JSONPath)
	assert.Equal(t, "documentation/CLI.md", cfg.MarkdownPath)
	assert.Equal(t, "documentation/cli-surface-allow.txt", cfg.AllowlistPath)
	assert.Equal(t, "README.md", cfg.READMEPath, "the README is not under the docs walk root")
}

// TestNew_MarkdownPathTracksDocsWalkRoot is the config half of the §2.4
// doc-link defect: whatever generates the README's link to the markdown
// reference has one source of truth for that path, and it is this field.
// The rendered-link assertion lives with the renderer.
func TestNew_MarkdownPathTracksDocsWalkRoot(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.DocsWalkRoot = "documentation" })

	assert.Equal(t, "documentation/CLI.md", d.Config().MarkdownPath)
	assert.NotEqual(t, "docs/CLI.md", d.Config().MarkdownPath)
}

func TestNew_ExplicitPathBeatsTheDerivedDefault(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) {
		cfg.DocsWalkRoot = "documentation"
		cfg.JSONPath = "api/surface.json"
	})
	cfg := d.Config()

	assert.Equal(t, "api/surface.json", cfg.JSONPath, "an explicit value wins over the derived default")
	assert.Equal(t, "documentation/CLI.md", cfg.MarkdownPath, "and the two knobs do not fight")
}

func TestNew_ClonesSliceFields(t *testing.T) {
	dirs := []string{"cmd", "pkg"}
	d := newTestDocs(t, func(cfg *Config) { cfg.LintedGoDirs = dirs })

	dirs[0] = "mutated"

	assert.Equal(t, []string{"cmd", "pkg"}, d.Config().LintedGoDirs,
		"a caller mutating its own slice after New must not reach the library's config")
}

func TestConfig_ReturnsACopy(t *testing.T) {
	d := newTestDocs(t)

	cfg := d.Config()
	cfg.JSONPath = "mutated.json"
	cfg.LintedGoDirs[0] = "mutated"

	assert.Equal(t, "docs/cli-surface.json", d.Config().JSONPath,
		"Config returns a copy, so mutating it must not take effect")
	assert.Equal(t, []string{"cmd", "internal", "pkg"}, d.Config().LintedGoDirs,
		"including its slice fields")
}

func TestNew_RejectsARegionNameWithAnHTMLCommentEscape(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, SubcommandsRegion: "subcommands-->"})

	assert.Contains(t, msg, "Config.SubcommandsRegion")
}

func TestNew_RejectsARegionNameWithRegexMetacharacters(t *testing.T) {
	assert.Contains(t,
		newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, AliasesRegion: "alias(es"}),
		"Config.AliasesRegion")
	assert.Contains(t,
		newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, AliasesRegion: "alias[es"}),
		"Config.AliasesRegion")
	assert.Contains(t,
		newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, AliasesRegion: "alias*es"}),
		"Config.AliasesRegion")
	assert.Contains(t,
		newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, AliasesRegion: `alias\es`}),
		"Config.AliasesRegion")
}

// TestValidate_RejectsAnEmptyRegionName reaches validate directly because
// defaulting means New can never see an empty region name: the check guards a
// future edit to the defaulting rules, not a caller.
func TestValidate_RejectsAnEmptyRegionName(t *testing.T) {
	cfg := Config{RegenerateCommand: testRegenerateCommand}.withDefaults()
	cfg.SubcommandsRegion = ""

	err := cfg.validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Config.SubcommandsRegion")
}

// TestValidate_RejectsAnEmptyPathField is the SEC-1 check on the same footing:
// an empty path field would make every Join target the repository root, and
// defaulting means only a defaulting bug can produce one.
func TestValidate_RejectsAnEmptyPathField(t *testing.T) {
	cfg := Config{RegenerateCommand: testRegenerateCommand}.withDefaults()
	cfg.JSONPath = ""

	err := cfg.validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Config.JSONPath must not be empty")
}

// TestNew_AcceptsBothLintScopeHalvesEmpty pins the removal of a rejection that
// was not true. Opting both configured halves out does not lint nothing: the
// markdown walk seeds from LintedMarkdown and then walks DocsWalkRoot
// unconditionally, so this configuration is "lint only the documentation tree",
// which is a plausible posture rather than a mistake. [LintScope] is the honest
// place to surface a run that really did reach nothing.
func TestNew_AcceptsBothLintScopeHalvesEmpty(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) {
		cfg.LintedMarkdown = []string{}
		cfg.LintedGoDirs = []string{}
	})
	cfg := d.Config()

	assert.NotNil(t, cfg.LintedMarkdown)
	assert.Empty(t, cfg.LintedMarkdown)
	assert.NotNil(t, cfg.LintedGoDirs)
	assert.Empty(t, cfg.LintedGoDirs)
}

func TestNew_HonoursAnExplicitlyEmptyLintScopeHalf(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.LintedMarkdown = []string{} })
	cfg := d.Config()

	assert.NotNil(t, cfg.LintedMarkdown,
		"an explicitly empty slice must survive as an empty slice; collapsing it to nil would re-enable the default")
	assert.Len(t, cfg.LintedMarkdown, 0, "an explicitly empty slice opts out; only a nil slice takes the default")
	assert.Equal(t, []string{"cmd", "internal", "pkg"}, cfg.LintedGoDirs)
}

func TestNew_LintedMarkdownDefaultTracksREADMEPath(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.READMEPath = "docs/index.md" })

	assert.Equal(t, []string{"docs/index.md"}, d.Config().LintedMarkdown)
}

func TestGeneratedPaths_ListsTheThreeArtifactsInStableOrder(t *testing.T) {
	d := newTestDocs(t)

	assert.Equal(t, []string{"docs/cli-surface.json", "docs/CLI.md", "README.md"}, d.GeneratedPaths())
}

// TestNew_RejectsAnEmptyLintScopeEntry is the reachable half of the empty-path
// rule: the scalar path fields are defaulted before validate sees them, but a
// slice entry is not, so an empty entry arrives exactly as the caller wrote it.
// Left unchecked it would widen the Go comment walk from the named roots to the
// whole repository.
func TestNew_RejectsAnEmptyLintScopeEntry(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, LintedGoDirs: []string{""}})

	assert.Contains(t, msg, "Config.LintedGoDirs[0] must not be empty")
}

func TestNew_RejectsAnAbsoluteLintScopeEntry(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, LintedGoDirs: []string{"/etc"}})

	assert.Contains(t, msg, "Config.LintedGoDirs[0]")
	assert.Contains(t, msg, "repository-relative")
}

func TestNew_RejectsAParentTraversalLintScopeEntry(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, LintedMarkdown: []string{"../../secrets.md"}})

	assert.Contains(t, msg, "Config.LintedMarkdown[0]")
	assert.Contains(t, msg, "..")
}

func TestNew_NamesTheOffendingLintScopeEntryByItsIndex(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, LintedGoDirs: []string{"cmd", "../outside"}})

	assert.Contains(t, msg, "Config.LintedGoDirs[1]", "the index must point at the entry at fault")
	assert.NotContains(t, msg, "Config.LintedGoDirs[0]", "and must not accuse the valid entry beside it")
}

func TestNew_RejectsIdenticalRegionNames(t *testing.T) {
	msg := newTestDocsError(t, Config{
		RegenerateCommand: testRegenerateCommand,
		SubcommandsRegion: "cli-tables",
		AliasesRegion:     "cli-tables",
	})

	assert.Contains(t, msg, "Config.SubcommandsRegion", "one marker pair cannot hold both generated tables")
	assert.Contains(t, msg, "Config.AliasesRegion")
}

// TestNew_RejectsCollidingArtifactPaths covers the destructive case: two
// artifact paths naming one file means generation overwrites one artifact with
// another, and GeneratedPaths reports the same name twice, so the staging list
// and the drift report both read as if nothing were wrong.
func TestNew_RejectsCollidingArtifactPaths(t *testing.T) {
	tests := map[string]struct {
		mod    func(*Config)
		fields []string
	}{
		"markdown reference over the consumer's README": {
			mod:    func(cfg *Config) { cfg.MarkdownPath = "README.md" },
			fields: []string{"Config.MarkdownPath", "Config.READMEPath"},
		},
		"json artifact over the markdown reference": {
			mod:    func(cfg *Config) { cfg.JSONPath, cfg.MarkdownPath = "docs/out", "docs/out" },
			fields: []string{"Config.JSONPath", "Config.MarkdownPath"},
		},
		"README relocated onto the markdown reference": {
			mod:    func(cfg *Config) { cfg.READMEPath = "docs/CLI.md" },
			fields: []string{"Config.MarkdownPath", "Config.READMEPath"},
		},
		"json artifact over the hand-authored allowlist": {
			mod:    func(cfg *Config) { cfg.JSONPath = "docs/cli-surface-allow.txt" },
			fields: []string{"Config.JSONPath", "Config.AllowlistPath"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Config{RegenerateCommand: testRegenerateCommand}
			test.mod(&cfg)

			msg := newTestDocsError(t, cfg)

			for _, field := range test.fields {
				assert.Contains(t, msg, field, "the error must name both colliding fields")
			}
		})
	}
}

// TestNew_RejectsACollisionHiddenByAnUncleanedPath is why the collision check
// compares cleaned paths: "./docs/CLI.md" and "docs/CLI.md" are one file, and a
// literal string comparison would let the destructive case through on a keystroke.
func TestNew_RejectsACollisionHiddenByAnUncleanedPath(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, JSONPath: "./docs/CLI.md"})

	assert.Contains(t, msg, "Config.JSONPath")
	assert.Contains(t, msg, "Config.MarkdownPath")
}

// TestNew_CleansScalarPathFields replaces a test that pinned the opposite --
// verbatim storage, on the reasoning that a path field is artifact content and
// the caller's spelling should reach the committed bytes. That reasoning left
// out the comparisons. A stored path field is matched against paths the
// documentation walk produced, and those are cleaned, so an uncleaned field
// silently fails to match itself; see
// TestIssueInAGeneratedFileIsRecognisedThroughAnUncleanedPath for what that
// cost. Cleaning is the narrowest normalisation that makes the comparisons
// hold, and every spelling it changes names the same file.
func TestNew_CleansScalarPathFields(t *testing.T) {
	tests := map[string]struct{ given, want string }{
		"a leading dot slash":   {"./docs/CLI.md", "docs/CLI.md"},
		"a doubled slash":       {"docs//CLI.md", "docs/CLI.md"},
		"a trailing slash":      {"docs/reference/", "docs/reference"},
		"an interior dot":       {"docs/./CLI.md", "docs/CLI.md"},
		"an already clean path": {"docs/CLI.md", "docs/CLI.md"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			d := newTestDocs(t, func(cfg *Config) { cfg.MarkdownPath = test.given })

			assert.Equal(t, test.want, d.Config().MarkdownPath)
		})
	}
}

// TestNew_CleansTheWalkRootAndThePathsDerivedFromIt covers the field the other
// four are joined onto: an uncleaned DocsWalkRoot would reach the documentation
// walk as given while the paths derived from it arrived cleaned by path.Join.
func TestNew_CleansTheWalkRootAndThePathsDerivedFromIt(t *testing.T) {
	cfg := newTestDocs(t, func(cfg *Config) { cfg.DocsWalkRoot = "./reference/" }).Config()

	assert.Equal(t, "reference", cfg.DocsWalkRoot)
	assert.Equal(t, "reference/cli-surface.json", cfg.JSONPath)
	assert.Equal(t, "reference/CLI.md", cfg.MarkdownPath)
	assert.Equal(t, "reference/cli-surface-allow.txt", cfg.AllowlistPath)
}

// TestNew_StillRejectsAParentTraversalRatherThanCleaningItAway is why cleaning
// runs after validate rather than before. path.Clean resolves ".." against the
// element in front of it, so cleaning first would turn "docs/../outside.json"
// into the perfectly valid "outside.json" and quietly widen where a Docs writes.
func TestNew_StillRejectsAParentTraversalRatherThanCleaningItAway(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, JSONPath: "docs/../outside.json"})

	assert.Contains(t, msg, "Config.JSONPath")
	assert.Contains(t, msg, "..")
	assert.Contains(t, msg, "docs/../outside.json", "and the message quotes the spelling the caller wrote")
}

// TestNew_StillRejectsAParentTraversalLintScopeEntryRatherThanCleaningItAway is
// the slice half of TestNew_StillRejectsAParentTraversalRatherThanCleaningItAway,
// and the reason cleaning has to run after validation for every path field
// rather than for the scalar ones alone. path.Clean resolves ".." against the
// element in front of it, so a lint-scope entry cleaned before validate saw it
// arrived as a perfectly valid path naming a different tree: "cmd/.." widens the
// Go comment walk from cmd to the whole repository, and "cmd/../internal"
// silently retargets it to a directory the caller never named. "pkg/../.." keeps
// its leading traversal and was rejected either way, but only on the cleaned
// spelling -- so the message quoted a path the caller never wrote.
func TestNew_StillRejectsAParentTraversalLintScopeEntryRatherThanCleaningItAway(t *testing.T) {
	spellings := map[string]string{
		"widens the walk to the whole repository":  "cmd/..",
		"retargets the walk to a sibling tree":     "cmd/../internal",
		"retargets it outside the tree named":      "docs/../outside",
		"keeps a leading traversal after cleaning": "pkg/../..",
	}
	fields := map[string]func(*Config, string){
		"LintedGoDirs":   func(cfg *Config, value string) { cfg.LintedGoDirs = []string{value} },
		"LintedMarkdown": func(cfg *Config, value string) { cfg.LintedMarkdown = []string{value} },
	}

	for field, set := range fields {
		for name, spelling := range spellings {
			t.Run(field+"/"+name, func(t *testing.T) {
				cfg := Config{RegenerateCommand: testRegenerateCommand}
				set(&cfg, spelling)

				msg := newTestDocsError(t, cfg)

				assert.Contains(t, msg, "Config."+field+"[0]")
				assert.Contains(t, msg, `must not contain a ".." element`)
				assert.Contains(t, msg, spelling, "and the message quotes the spelling the caller wrote")
			})
		}
	}
}

// TestCleanScalarPathLeavesAnEmptyPathEmpty guards the trap cleanPathEntries
// already documents: path.Clean("") is ".", so cleaning an empty path field
// would replace a missing path with one naming the walk's own root. No
// configuration can reach it -- withDefaults fills every scalar path field and
// validate rejects an empty one before cleaning runs -- so the guard is
// exercised directly, which is also what keeps it from being dropped as dead
// code by whoever adds the next path field.
func TestCleanScalarPathLeavesAnEmptyPathEmpty(t *testing.T) {
	assert.Equal(t, "", cleanScalarPath(""), "path.Clean would answer \".\"")
	assert.Equal(t, "docs", cleanScalarPath("./docs/"))
}

// TestCleanPathEntriesLeavesAnEmptyEntryEmpty is the slice twin of the guard
// above, and it is exercised directly for the same reason: cleaning runs after
// validate, which has already rejected an empty entry by name, so no
// configuration reaches the carve-out through New. Left untested it reads as
// dead code to whoever touches cleanPathEntries next -- and dropping it would
// turn the empty entry validate names into a silent walk of the entire
// repository the moment the two ever ran in the other order again.
func TestCleanPathEntriesLeavesAnEmptyEntryEmpty(t *testing.T) {
	assert.Equal(t,
		[]string{"", "docs/guide.md", "pkg"},
		cleanPathEntries([]string{"", "./docs/guide.md", "pkg/"}),
		"path.Clean would answer \".\" for the empty entry")
}

// TestNew_RejectsABackslashPathField closes a gap that only shows on POSIX:
// filepath.ToSlash is the identity there, so both halves of the absolute-path
// predicate are the POSIX one and a Windows-shaped path slipped through as an
// ordinary relative name.
func TestNew_RejectsABackslashPathField(t *testing.T) {
	for _, value := range []string{
		`C:\Users\me\out.json`,
		`\\host\share\out.json`,
		`\etc\passwd`,
		`..\..\etc\passwd`,
	} {
		t.Run(value, func(t *testing.T) {
			msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, JSONPath: value})

			assert.Contains(t, msg, "Config.JSONPath")
			assert.Contains(t, msg, "forward slashes")
		})
	}
}

func TestNew_RejectsABackslashLintScopeEntry(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, LintedGoDirs: []string{`cmd\internal`}})

	assert.Contains(t, msg, "Config.LintedGoDirs[0]")
	assert.Contains(t, msg, "forward slashes")
}

// TestNew_IsIdempotentForAnExplicitlyEmptyLintScopeHalf feeds a resolved Config
// straight back into New, which is what a consumer wrapping this package does.
// The opt-out must survive the round trip: were an empty slice to collapse to
// nil anywhere along it, the second New would silently re-enable the very lint
// scope the caller opted out of.
func TestNew_IsIdempotentForAnExplicitlyEmptyLintScopeHalf(t *testing.T) {
	first := newTestDocs(t, func(cfg *Config) { cfg.LintedMarkdown = []string{} }).Config()

	second := newTestDocs(t, func(cfg *Config) { *cfg = first }).Config()

	assert.NotNil(t, second.LintedMarkdown, "the round trip must not turn the opt-out back into a default")
	assert.Len(t, second.LintedMarkdown, 0)
	assert.Equal(t, first, second, "a resolved Config must be a fixed point of New")
}

// TestNew_CleansSlicePathEntries is the C4 half of the cleaning rule, and the
// reason cleanPaths must still clean the slice fields once validate has passed:
// left uncleaned, "./docs/guide.md" and the "docs/guide.md" the documentation
// walk produces are two distinct strings that slices.Compact cannot merge, so
// the file is linted twice -- every issue in it reported twice and the coverage
// sentence counting it twice.
func TestNew_CleansSlicePathEntries(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) {
		cfg.LintedMarkdown = []string{"./docs/guide.md", "docs/"}
		cfg.LintedGoDirs = []string{"./pkg", "internal/"}
	})
	cfg := d.Config()

	assert.Equal(t, []string{"docs/guide.md", "docs"}, cfg.LintedMarkdown)
	assert.Equal(t, []string{"pkg", "internal"}, cfg.LintedGoDirs)
}

// TestNew_RejectsAPathContainingAngleBrackets is the S3 check. MarkdownPath is
// interpolated raw into the generated alias region's body, so a path carrying a
// region end marker splices a second marker into the README on the first Write.
// Every later Write and the drift gate itself then hard-error with "found 2",
// and hand repair is the only exit -- the same reason region names are held to
// a charset.
func TestNew_RejectsAPathContainingAngleBrackets(t *testing.T) {
	for _, value := range []string{
		"docs/CLI<!-- END generated: cli-aliases -->.md",
		"docs/<CLI>.md",
		"docs/a>b.md",
	} {
		t.Run(value, func(t *testing.T) {
			msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, MarkdownPath: value})

			assert.Contains(t, msg, "Config.MarkdownPath")
			assert.Contains(t, msg, "must not contain")
		})
	}
}

func TestNew_RejectsAngleBracketsInALintScopeEntry(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, LintedMarkdown: []string{"docs/<x>.md"}})

	assert.Contains(t, msg, "Config.LintedMarkdown[0]")
}

// TestNew_RejectsArtifactPathsDifferingOnlyInCase is the S4 check. On APFS and
// NTFS two paths differing only in case are one file: New accepts them, the
// second artifact clobbers the first, and CheckArtifacts then reports permanent
// staleness immediately after a successful Write -- a red gate that no correct
// regeneration can clear. A Config is portable content by design, so the rule
// is deliberately applied on case-sensitive filesystems too.
func TestNew_RejectsArtifactPathsDifferingOnlyInCase(t *testing.T) {
	msg := newTestDocsError(t, Config{RegenerateCommand: testRegenerateCommand, JSONPath: "docs/cli.MD"})

	assert.Contains(t, msg, "Config.JSONPath")
	assert.Contains(t, msg, "Config.MarkdownPath")
	assert.Contains(t, msg, `"docs/cli.MD"`, "the message keeps both original spellings")
	assert.Contains(t, msg, `"docs/CLI.md"`)
}

// TestNew_RejectsARegenerateCommandThatCorruptsTheGeneratedNotice is the S5
// check. The value is concatenated raw into the artifact's leading HTML comment
// and into a markdown code span, so "-->" closes the comment early and leaves
// the remainder as rendered body, a newline injects a heading, and a backtick
// breaks the span.
func TestNew_RejectsARegenerateCommandThatCorruptsTheGeneratedNotice(t *testing.T) {
	for name, value := range map[string]string{
		"closes the generated notice early": "make docs --> # ",
		"injects a line of its own":         "make docs\n# owned",
		"breaks the markdown code span":     "make docs `x`",
	} {
		t.Run(name, func(t *testing.T) {
			msg := newTestDocsError(t, Config{RegenerateCommand: value})

			assert.Contains(t, msg, "Config.RegenerateCommand")
		})
	}
}
