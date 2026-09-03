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

func TestNew_RejectsAConfigurationThatWouldLintNothing(t *testing.T) {
	msg := newTestDocsError(t, Config{
		RegenerateCommand: testRegenerateCommand,
		LintedMarkdown:    []string{},
		LintedGoDirs:      []string{},
	})

	assert.Contains(t, msg, "would lint nothing")
}

func TestNew_HonoursAnExplicitlyEmptyLintScopeHalf(t *testing.T) {
	d := newTestDocs(t, func(cfg *Config) { cfg.LintedMarkdown = []string{} })
	cfg := d.Config()

	assert.Empty(t, cfg.LintedMarkdown, "an explicitly empty slice opts out; only a nil slice takes the default")
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
