package clisurface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withContributing configures the second hand-written document several fixtures
// below are about. The pinned package linted CONTRIBUTING.md by default; this
// one defaults to the README alone, because a consumer's repository need not
// have a CONTRIBUTING.md and a default that names a missing file makes
// [Docs.LintRepo] fail on a correct repository. A test whose subject is "a
// second hand-written document" therefore names it.
func withContributing(c *Config) {
	c.LintedMarkdown = []string{"README.md", "CONTRIBUTING.md"}
}

// newFakeRepo lays out a temporary repository for d: a go.mod so [FindRepoRoot]
// resolves against it, the configured documentation walk root, and a README
// carrying both generated regions. It returns the root.
func newFakeRepo(t *testing.T, d *Docs) string {
	t.Helper()

	cfg := d.Config()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, cfg.DocsWalkRoot), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/tool\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, cfg.READMEPath), []byte(strings.Join([]string{
		"# tool",
		"",
		"## Quick Start",
		"",
		beginMarker(cfg.SubcommandsRegion),
		"stale listing",
		endMarker(cfg.SubcommandsRegion),
		"",
		beginMarker(cfg.AliasesRegion),
		"stale aliases",
		endMarker(cfg.AliasesRegion),
		"",
		"hand-written tail",
		"",
	}, "\n")), 0o644))
	return root
}

// readAll reads every generated artifact into a map keyed by repo-relative path.
func readAll(t *testing.T, d *Docs, root string) map[string]string {
	t.Helper()

	out := map[string]string{}
	for _, rel := range d.GeneratedPaths() {
		content, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err)
		out[rel] = string(content)
	}
	return out
}

func TestArtifactsRendersEveryGeneratedFile(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())

	artifacts, err := d.artifacts(root, s)
	require.NoError(t, err)

	require.Len(t, artifacts, 3)
	cfg := d.Config()
	assert.Equal(t, []string{cfg.JSONPath, cfg.MarkdownPath, cfg.READMEPath}, []string{
		artifacts[0].Path, artifacts[1].Path, artifacts[2].Path,
	}, "artifacts come back in a stable order")
	assert.Equal(t, d.GeneratedPaths(), []string{artifacts[0].Path, artifacts[1].Path, artifacts[2].Path})

	readme := string(artifacts[2].Content)
	assert.Contains(t, readme, "hand-written tail", "the hand-written parts of the README survive")
	assert.NotContains(t, readme, "stale listing", "the generated region is replaced")
	assert.Contains(t, readme, "| `scan` | `sc`, `scanner` |")
}

func TestArtifactsFailsLoudlyWhenTheREADMEHasNoRegionMarkers(t *testing.T) {
	d := newTestDocs(t)
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, d.Config().READMEPath), []byte("# tool\n"), 0o644))

	_, err := d.artifacts(root, Walk(newTestTree()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `splicing region "cli-subcommands" into README.md`)
}

func TestArtifactsFailsWhenTheREADMEIsMissing(t *testing.T) {
	d := newTestDocs(t)

	_, err := d.artifacts(t.TempDir(), Walk(newTestTree()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading README.md")
}

func TestWriteThenCheckIsClean(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())

	require.NoError(t, d.Write(root, s))

	stale, err := d.CheckArtifacts(root, s)
	require.NoError(t, err)
	assert.Empty(t, stale, "freshly written artifacts are not stale")

	for _, rel := range d.GeneratedPaths() {
		_, statErr := os.Stat(filepath.Join(root, rel))
		require.NoError(t, statErr, "%s must exist on disk", rel)
	}
}

func TestWriteIsIdempotent(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())

	require.NoError(t, d.Write(root, s))
	first := readAll(t, d, root)
	require.NoError(t, d.Write(root, s))
	second := readAll(t, d, root)

	assert.Equal(t, first, second, "regenerating twice must produce byte-identical files")
}

func TestCheckArtifactsNamesTheStaleFileAndTheFirstDifference(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	// Hand-edit the generated reference, the way a well-meaning contributor would.
	mdPath := filepath.Join(root, d.Config().MarkdownPath)
	content, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	edited := strings.Replace(string(content), "# tool CLI reference", "# Tool CLI Reference", 1)
	require.NoError(t, os.WriteFile(mdPath, []byte(edited), 0o644))

	stale, err := d.CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 1)
	assert.Equal(t, d.Config().MarkdownPath, stale[0].Path)
	assert.Contains(t, stale[0].Detail, `line 3 is "# Tool CLI Reference", generated content has "# tool CLI reference"`)
	assert.Contains(t, stale[0].String(), "docs/CLI.md is stale")
	assert.Contains(t, stale[0].String(), "Regenerate it with '"+testRegenerateCommand+"'")
}

func TestCheckArtifactsReportsMissingFiles(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())

	stale, err := d.CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 3, "nothing has been generated yet: the JSON and markdown are missing and the README is stale")
	assert.Equal(t, d.Config().JSONPath, stale[0].Path)
	assert.Contains(t, stale[0].Detail, "cannot be read")
}

func TestCheckArtifactsReportsATruncatedFile(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	// A truncation that keeps every surviving line identical can only be
	// described by the line counts.
	jsonPath := filepath.Join(root, d.Config().JSONPath)
	full, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	truncated := strings.Join(strings.Split(string(full), "\n")[:3], "\n")
	require.NoError(t, os.WriteFile(jsonPath, []byte(truncated), 0o644))

	stale, err := d.CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 1)
	assert.Equal(t, d.Config().JSONPath, stale[0].Path)
	assert.Contains(t, stale[0].Detail, "committed content has 3 lines, generated content has")
}

// TestStalenessRendersSafelyOnTheZeroValue pins the cost of stamping: a
// Staleness a caller built itself has no regenerate command to name, and must
// still render rather than panic.
func TestStalenessRendersSafelyOnTheZeroValue(t *testing.T) {
	assert.NotPanics(t, func() { _ = Staleness{}.String() })

	line := Staleness{Path: "docs/CLI.md", Detail: "differs"}.String()
	assert.Contains(t, line, "docs/CLI.md is stale: differs")
	assert.NotContains(t, line, testRegenerateCommand,
		"an unstamped staleness must not invent a command the caller never configured")
}

func TestLintRepoChecksMarkdownAndGoComments(t *testing.T) {
	d := newTestDocs(t, withContributing)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.WriteFile(filepath.Join(root, "CONTRIBUTING.md"),
		[]byte("Run `tool scan --target host`.\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "guide.md"),
		[]byte("```bash\ntool scan --removed-flag\n```\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cmd", "tool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cmd", "tool", "main.go"),
		[]byte("package main\n\n// handles the --gone-from-comments mode.\nfunc main() {}\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pkg", "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pkg", "lib", "lib.go"),
		[]byte("package lib\n\n// Uses --timeout, which still exists.\nconst A = 1\n"), 0o644))

	issues, _, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 2)
	assert.Equal(t, "cmd/tool/main.go", issues[0].File, "issues are sorted by file then line")
	assert.Equal(t, "--gone-from-comments", issues[0].Token)
	assert.Equal(t, "docs/guide.md", issues[1].File)
	assert.Equal(t, "--removed-flag", issues[1].Token)
}

func TestLintRepoAcceptsTheDocumentsItJustGenerated(t *testing.T) {
	d := newTestDocs(t, withContributing)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))
	require.NoError(t, os.WriteFile(filepath.Join(root, "CONTRIBUTING.md"),
		[]byte("Run `"+testRegenerateCommand+"`.\n"), 0o644))

	issues, _, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues,
		"the generated reference and README regions must lint clean against the surface they came from")
}

func TestLintRepoSurvivesAMissingDocsDirectory(t *testing.T) {
	d := newTestDocs(t, withContributing)
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("# tool\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "CONTRIBUTING.md"), []byte("hi\n"), 0o644))

	issues, scope, err := d.LintRepo(root, Walk(newTestTree()), emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues)
	assert.Equal(t, []string{"CONTRIBUTING.md", "README.md"}, scope.MarkdownFiles,
		"a missing walk root contributes no documents, and says so")
}

func TestLintRepoFailsWhenAConfiguredDocumentIsMissing(t *testing.T) {
	d := newTestDocs(t, withContributing)
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("# tool\n"), 0o644))

	_, _, err := d.LintRepo(root, Walk(newTestTree()), emptyAllowlist(t))
	require.Error(t, err, "a document the linter is configured to read must not be skipped silently")
	assert.Contains(t, err.Error(), "reading CONTRIBUTING.md")
}

// TestLintRepoWalksNestedDocsDirectories pins the recursive documentation walk.
// A document in docs/guides/ names removed flags exactly as effectively as one
// in docs/, and a check with a silent blind spot is worse than one whose reach
// is obvious.
func TestLintRepoWalksNestedDocsDirectories(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "guides", "deep"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "guides", "nested.md"),
		[]byte("```bash\ntool scan --nested-gone\n```\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "guides", "deep", "deeper.md"),
		[]byte("```bash\ntool scan --deeper-gone\n```\n"), 0o644))

	issues, _, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 2, "both nested documents must be reached")
	assert.Equal(t, "docs/guides/deep/deeper.md", issues[0].File)
	assert.Equal(t, "--deeper-gone", issues[0].Token)
	assert.Equal(t, "docs/guides/nested.md", issues[1].File)
	assert.Equal(t, "--nested-gone", issues[1].Token)
}

// TestLintRepoWalksTheConfiguredDocumentationRoot pins the second hard-coded
// path the port removed: the tree that gets walked for markdown is whatever
// DocsWalkRoot names, and nothing else is reached.
func TestLintRepoWalksTheConfiguredDocumentationRoot(t *testing.T) {
	d := newTestDocs(t, func(c *Config) { c.DocsWalkRoot = "documentation" })
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.WriteFile(filepath.Join(root, "documentation", "notes.md"),
		[]byte("```bash\ntool scan --walked-here\n```\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "ignored.md"),
		[]byte("```bash\ntool scan --not-walked\n```\n"), 0o644))

	issues, scope, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 1, "only the configured root is walked")
	assert.Equal(t, "documentation/notes.md", issues[0].File)
	assert.Equal(t, "--walked-here", issues[0].Token)
	assert.Contains(t, scope.MarkdownFiles, "documentation/notes.md")
	assert.NotContains(t, scope.MarkdownFiles, "docs/ignored.md",
		"the default root is not walked once the consumer names another one")
}

// TestLintRepoReachesGoComments is the reachability proof for the Go-comment
// linter. Its own tests call it directly, so they would keep passing if
// LintRepo stopped calling it and it shipped unreachable; this fixture's only
// defect lives in a Go comment, so nothing but LintRepo's call can report it.
func TestLintRepoReachesGoComments(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "internal", "engine"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "internal", "engine", "engine.go"),
		[]byte("package engine\n\n// Run honors the --gone-from-comments mode.\nfunc Run() {}\n"), 0o644))

	issues, scope, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)

	require.Len(t, issues, 1, "the Go comment is the only defect in this repository")
	assert.Equal(t, "internal/engine/engine.go", issues[0].File)
	assert.Equal(t, "--gone-from-comments", issues[0].Token)
	assert.Contains(t, scope.GoFiles, "internal/engine/engine.go")
}

// TestLintRepoReportsTheScopeItActuallyWalked pins the scope to the walk rather
// than to the configuration. pkg/ is configured and absent: the run must leave
// it out of the reported scope, because a directory nobody ever opened is not
// coverage, and a report that names it as covered is worse than one that says
// nothing -- it asserts a reach the run did not have.
func TestLintRepoReportsTheScopeItActuallyWalked(t *testing.T) {
	d := newTestDocs(t, func(c *Config) { c.LintedGoDirs = []string{"cmd", "pkg"} })
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "cmd", "tool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cmd", "tool", "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "internal", "engine"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "internal", "engine", "engine.go"),
		[]byte("package engine\n\n// Run honors the --gone-from-comments mode.\nfunc Run() {}\n"), 0o644))

	allow, err := d.ParseAllowlist("--old-name # renamed in v1.9, the migration note has to name it\n")
	require.NoError(t, err)

	issues, scope, err := d.LintRepo(root, s, allow)
	require.NoError(t, err)
	assert.Empty(t, issues, "internal/ is not configured, so its defect is out of scope")

	assert.Equal(t, []string{"README.md", "docs/CLI.md"}, scope.MarkdownFiles)
	assert.Equal(t, []string{"cmd"}, scope.GoDirs, "the directories the walk actually opened")
	assert.Equal(t, []string{"cmd/tool/main.go"}, scope.GoFiles, "the files the walk actually found")
	assert.Equal(t, allow, scope.Allowlist)

	assert.Contains(t, LintReport(issues, scope),
		"Linted 2 markdown file(s) [README.md, docs/CLI.md] and 1 Go file(s) under 1 Go dir(s) [cmd], with 1 token(s) allowlisted.",
		"the report states the coverage the run really had")
}

// TestLintRepoOmitsAConfiguredGoDirectoryThatIsNotThere is the counterpart the
// scope test above cannot state on its own: a directory that is merely
// configured must not be reported as walked, while one that exists and holds no
// Go files must be, contributing zero files.
//
// The failure it locks out is silent. A consumer renames or typos an entry in
// LintedGoDirs, Go-comment coverage for that tree drops to zero, and a scope
// echoing the configuration back still names the directory as covered -- in
// exactly the case where a silent gate is most dangerous.
func TestLintRepoOmitsAConfiguredGoDirectoryThatIsNotThere(t *testing.T) {
	d := newTestDocs(t, func(c *Config) { c.LintedGoDirs = []string{"cmd", "empty", "typoed"} })
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "cmd", "tool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cmd", "tool", "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644))
	// "empty" exists and holds no Go file; "typoed" does not exist at all.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "empty", "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "empty", "notes.txt"), []byte("no Go here\n"), 0o644))

	issues, scope, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)
	assert.Empty(t, issues)

	assert.Equal(t, []string{"cmd", "empty"}, scope.GoDirs,
		"an existing directory holding no Go files is still coverage; a missing one is not")
	assert.NotContains(t, scope.GoDirs, "typoed",
		"a directory the walk never opened must not be reported as walked")
	assert.Equal(t, []string{"cmd/tool/main.go"}, scope.GoFiles)

	assert.Contains(t, LintReport(issues, scope),
		"1 Go file(s) under 2 Go dir(s) [cmd, empty]",
		"the coverage sentence counts only the directories the walk reached")
}

// TestLintRepoLintsADocumentUnderTheWalkRootExactlyOnce pins the deduplication
// of the markdown scope. Putting the README inside the documentation tree is a
// legitimate layout -- it is defaults plus one natural choice -- and it puts the
// configured document and the walk over the same file. Linting it twice emits
// every issue in it verbatim twice and double-counts the coverage sentence.
func TestLintRepoLintsADocumentUnderTheWalkRootExactlyOnce(t *testing.T) {
	d := newTestDocs(t, func(c *Config) { c.READMEPath = "docs/README.md" })
	require.Equal(t, []string{"docs/README.md"}, d.Config().LintedMarkdown,
		"the fixture only bites while the configured document is the one the walk reaches")

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "README.md"),
		[]byte("```bash\ntool scan --removed-flag\n```\n"), 0o644))

	issues, scope, err := d.LintRepo(root, Walk(newTestTree()), emptyAllowlist(t))
	require.NoError(t, err)

	assert.Equal(t, []string{"docs/README.md"}, scope.MarkdownFiles,
		"a document both the configured list and the walk reach is one document")
	require.Len(t, issues, 1,
		"one defect in one file is one issue, not one per path that named the file")
	assert.Equal(t, "--removed-flag", issues[0].Token)
}

// TestLintRepoLintsAGoFileUnderTwoConfiguredDirectoriesOnce is the same defect
// on the other walk: nothing stops a consumer naming a directory and a
// directory beneath it, and New accepts both.
func TestLintRepoLintsAGoFileUnderTwoConfiguredDirectoriesOnce(t *testing.T) {
	d := newTestDocs(t, func(c *Config) { c.LintedGoDirs = []string{"pkg", "pkg/lib"} })
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "pkg", "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pkg", "lib", "lib.go"),
		[]byte("package lib\n\n// Uses the --gone-from-comments mode.\nconst A = 1\n"), 0o644))

	issues, scope, err := d.LintRepo(root, s, emptyAllowlist(t))
	require.NoError(t, err)

	assert.Equal(t, []string{"pkg/lib/lib.go"}, scope.GoFiles,
		"a file two configured trees both contain is one file")
	require.Len(t, issues, 1, "and its one defect is one issue")
	assert.Equal(t, "--gone-from-comments", issues[0].Token)
}

func TestLoadAllowlist(t *testing.T) {
	d := newTestDocs(t)
	root := t.TempDir()

	allow, err := d.LoadAllowlist(root)
	require.NoError(t, err, "a missing allowlist is an empty allowlist, not an error")
	assert.Empty(t, allow.Entries())

	allowlistPath := filepath.Join(root, d.Config().AllowlistPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(allowlistPath), 0o755))
	require.NoError(t, os.WriteFile(allowlistPath,
		[]byte("--old-name # renamed in v1.9, the migration note has to name it\n"), 0o644))

	allow, err = d.LoadAllowlist(root)
	require.NoError(t, err)
	assert.Equal(t, []string{"--old-name"}, allow.Entries())

	require.NoError(t, os.WriteFile(allowlistPath, []byte("--no-reason\n"), 0o644))
	_, err = d.LoadAllowlist(root)
	require.Error(t, err, "an entry without a reason is a hard error")
}

func TestFindRepoRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/tool\n"), 0o644))
	nested := filepath.Join(root, "cmd", "tool")
	require.NoError(t, os.MkdirAll(nested, 0o755))

	found, err := FindRepoRoot(nested)
	require.NoError(t, err)
	assert.Equal(t, root, found, "the root is the nearest ancestor holding go.mod")

	_, err = FindRepoRoot(filepath.Join(t.TempDir(), "nowhere"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no go.mod found")
}

// TestCheckArtifactsToleratesCRLF checks that a checkout's line-ending
// convention cannot look like documentation drift. A repository carrying no
// .gitattributes leaves a contributor with core.autocrlf=true holding CRLF on
// disk while the renderers emit LF.
func TestCheckArtifactsToleratesCRLF(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	for _, rel := range d.GeneratedPaths() {
		path := filepath.Join(root, rel)
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		crlf := strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n", "\r\n")
		require.NoError(t, os.WriteFile(path, []byte(crlf), 0o644))
	}

	stale, err := d.CheckArtifacts(root, s)
	require.NoError(t, err)
	assert.Empty(t, stale, "CRLF line endings are not drift")
}

// TestCheckArtifactsStillCatchesRealDriftInACRLFCheckout guards the tolerance
// above from swallowing a genuine difference.
func TestCheckArtifactsStillCatchesRealDriftInACRLFCheckout(t *testing.T) {
	d := newTestDocs(t)
	root := newFakeRepo(t, d)
	s := Walk(newTestTree())
	require.NoError(t, d.Write(root, s))

	path := filepath.Join(root, d.Config().MarkdownPath)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	edited := strings.ReplaceAll(string(content), "--timeout", "--timeuot")
	require.NotEqual(t, string(content), edited, "the fixture must actually change")
	require.NoError(t, os.WriteFile(path, []byte(strings.ReplaceAll(edited, "\n", "\r\n")), 0o644))

	stale, err := d.CheckArtifacts(root, s)
	require.NoError(t, err)

	require.Len(t, stale, 1)
	assert.Equal(t, d.Config().MarkdownPath, stale[0].Path)
	assert.NotContains(t, stale[0].Detail, `\r`, "the reported line must not be noisy with carriage returns")
}

// TestArtifactGateReddens is the meta-test: it drives the whole gate end to end
// and proves it goes red when the CLI moves under the committed documentation.
// Every other test here checks one piece; a gate whose red path is never
// exercised is a gate that can silently stop working while its suite stays
// green.
func TestArtifactGateReddens(t *testing.T) {
	const allowlistPath = "docs/deliberate-mentions.txt"

	d := newTestDocs(t, func(c *Config) { c.AllowlistPath = allowlistPath })
	root := newFakeRepo(t, d)

	documented := Walk(newTestTree())
	require.NoError(t, d.Write(root, documented))

	// The gate discovers the repository root the way a test running in a
	// package directory does, then reads back what was committed.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cmd", "tool"), 0o755))
	found, err := FindRepoRoot(filepath.Join(root, "cmd", "tool"))
	require.NoError(t, err)
	require.Equal(t, root, found)

	committed, err := os.ReadFile(filepath.Join(found, d.Config().JSONPath))
	require.NoError(t, err)
	golden, err := d.ParseJSON(committed)
	require.NoError(t, err)

	require.Empty(t, Diff(golden, documented),
		"the fixture must start green, or nothing below proves the gate reddens")

	t.Run("renaming one registered flag is one removal and one addition", func(t *testing.T) {
		live := newTestTree()
		renamed := mustCommand(t, live, "scan").Flags().Lookup("target")
		require.NotNil(t, renamed, "the fixture tree must still carry the flag this test renames")
		renamed.Name = "targe"

		findings := Diff(golden, Walk(live))

		var removals, additions []Finding
		for _, f := range findings {
			switch f.Kind {
			case FlagRemoved:
				removals = append(removals, f)
			case FlagUndocumented:
				additions = append(additions, f)
			}
		}
		assert.Len(t, removals, 1, "exactly one flag left the surface")
		assert.Len(t, additions, 1, "exactly one flag arrived")
		assert.Len(t, findings, 2, "a rename is those two findings and nothing else")
		assert.Equal(t, "target", removals[0].Flag)
		assert.Equal(t, "targe", additions[0].Flag)
		assert.Equal(t, "tool scan", removals[0].Command)
	})

	t.Run("the fixture tree is restored for the next caller", func(t *testing.T) {
		assert.Empty(t, Diff(golden, Walk(newTestTree())),
			"newTestTree hands out a fresh tree, so the rename above cannot leak")
	})

	t.Run("the committed artifacts go stale with the tree", func(t *testing.T) {
		live := newTestTree()
		mustCommand(t, live, "scan").Flags().Lookup("target").Name = "targe"

		stale, err := d.CheckArtifacts(root, Walk(live))
		require.NoError(t, err)
		require.NotEmpty(t, stale, "a renamed flag makes every artifact that names it stale")
		assert.Contains(t, stale[0].String(), "Regenerate it with '"+testRegenerateCommand+"'")
	})

	t.Run("a document naming a removed flag names the configured allowlist", func(t *testing.T) {
		issues := d.LintMarkdown(documented, "docs/guide.md",
			"```bash\ntool scan --removed-flag\n```\n", emptyAllowlist(t))

		require.Len(t, issues, 1)
		assert.Contains(t, issues[0].String(), allowlistPath,
			"the advice names this Docs's allowlist, not a package-level default")
		assert.NotContains(t, issues[0].String(), defaultAllowlistName)
	})
}
