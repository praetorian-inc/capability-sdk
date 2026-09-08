package clisurface

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// FindRepoRoot walks up from start until it finds the directory holding go.mod. A
// drift gate usually runs as a test, whose working directory is the package
// directory, so it needs the root to resolve the repo-relative paths [Config] names.
// Only a regular go.mod counts: os.Stat would let a directory named go.mod, or one
// symlinked out of the tree, win over the real module root above it.
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", start, err)
	}
	for {
		if info, statErr := os.Lstat(filepath.Join(dir, "go.mod")); statErr == nil && info.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found in %s or any parent directory", start)
		}
		dir = parent
	}
}

// artifact is one generated file and the content it must have.
type artifact struct {
	// Path is repo-relative.
	Path string
	// Content is the full file content the surface renders to. For the README
	// it is the on-disk file with the generated regions replaced.
	Content []byte
}

// artifacts renders every generated artifact for s. The README is spliced from
// its current on-disk content, so its hand-written parts are preserved.
func (d *Docs) artifacts(repoRoot string, s Surface) ([]artifact, error) {
	jsonBytes, err := d.renderJSON(s)
	if err != nil {
		return nil, err
	}

	// Guarded on the way in as [Docs.Write] guards on the way out: trust attaches
	// to the configured value, not what it resolves to, and reading through a
	// symlink splices a file from outside the repository into the artifacts. An
	// error, not a skip, so Write and [Docs.CheckArtifacts] agree.
	readmePath := filepath.Join(repoRoot, d.cfg.READMEPath)
	if isIrregular(readmePath) {
		return nil, fmt.Errorf("refusing to read %s: it exists and is not a regular file", d.cfg.READMEPath)
	}
	// #nosec G304 -- repoRoot joined with Config.READMEPath, which New rejects when absolute, backslashed or carrying "..", and isIrregular above refuses non-regular files.
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", d.cfg.READMEPath, err)
	}
	spliced := string(readme)
	for _, r := range d.renderRegions(s) {
		spliced, err = splice(spliced, r.Name, r.Body)
		if err != nil {
			return nil, fmt.Errorf("splicing region %q into %s: %w", r.Name, d.cfg.READMEPath, err)
		}
	}

	return []artifact{
		{Path: d.cfg.JSONPath, Content: jsonBytes},
		{Path: d.cfg.MarkdownPath, Content: d.renderMarkdown(s)},
		{Path: d.cfg.READMEPath, Content: []byte(spliced)},
	}, nil
}

// Write writes every generated artifact. This is the update path; the drift gate
// must never call it.
//
// An artifact path that already exists as something other than a regular file is
// refused rather than written through: [Config] validates a path's shape, and a
// shape cannot express where the path resolves to, so a symlinked docs/CLI.md would
// send an ordinary regeneration outside the repository. An error and never a skip,
// since a skipped artifact leaves [Docs.CheckArtifacts] reporting drift no
// regeneration can clear.
func (d *Docs) Write(repoRoot string, s Surface) error {
	artifacts, err := d.artifacts(repoRoot, s)
	if err != nil {
		return err
	}
	for i := range artifacts {
		path := filepath.Join(repoRoot, artifacts[i].Path)
		// #nosec G301 -- committed repository documentation: git tracks no directory mode, and 0o750 would break group traversal on shared CI checkouts.
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", artifacts[i].Path, err)
		}
		if isIrregular(path) {
			return fmt.Errorf("refusing to write %s: it already exists and is not a regular file", artifacts[i].Path)
		}
		// #nosec G306 -- tracked, world-readable documentation files; 0o644 is what git checks out, where 0o600 would leave a regenerated README owner-only.
		if err := os.WriteFile(path, artifacts[i].Content, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", artifacts[i].Path, err)
		}
	}
	return nil
}

// Staleness is a generated artifact whose committed content no longer matches
// what the surface renders.
type Staleness struct {
	// Path is the repo-relative artifact.
	Path string
	// Detail says how it differs, naming the first differing line.
	Detail string

	// regenerateCommand is the resolved [Config] value [Staleness.String] reports,
	// stamped in by the producing method (see stampStaleness) so String needs no
	// receiver. A caller-built Staleness renders without it.
	regenerateCommand string
}

// stampStaleness records the resolved [Config] value [Staleness.String] needs,
// so a rendered line names the command this Docs was configured with rather
// than a package-level default the consumer never chose.
func (d *Docs) stampStaleness(s Staleness) Staleness {
	s.regenerateCommand = d.cfg.RegenerateCommand
	return s
}

// String renders the staleness as one actionable line.
func (s Staleness) String() string {
	return fmt.Sprintf("%s is stale: %s. Regenerate it with '%s'", s.Path, s.Detail, s.regenerateCommand)
}

// CheckArtifacts compares the committed artifacts against what the surface renders,
// without writing anything. Line endings are normalized first, so a contributor
// holding CRLF on disk does not see every generated file reported as stale.
//
// An artifact that exists as something other than a regular file is an error rather
// than staleness: every [Staleness] renders as "Regenerate it with ...", and
// [Docs.Write] refuses that same file, so reporting drift would advise a repair that
// cannot run. A merely missing artifact stays staleness -- regenerating clears it.
func (d *Docs) CheckArtifacts(repoRoot string, s Surface) ([]Staleness, error) {
	artifacts, err := d.artifacts(repoRoot, s)
	if err != nil {
		return nil, err
	}

	var stale []Staleness
	for i := range artifacts {
		path := filepath.Join(repoRoot, artifacts[i].Path)
		if isIrregular(path) {
			return nil, fmt.Errorf("refusing to read %s: it exists and is not a regular file", artifacts[i].Path)
		}
		// #nosec G304 -- repoRoot joined with an artifact path derived from the validated Config, and isIrregular above refuses non-regular files.
		onDisk, readErr := os.ReadFile(path)
		if readErr != nil {
			stale = append(stale, d.stampStaleness(Staleness{
				Path:   artifacts[i].Path,
				Detail: "cannot be read (" + readErr.Error() + ")",
			}))
			continue
		}
		if bytes.Equal(normalizeNewlines(onDisk), normalizeNewlines(artifacts[i].Content)) {
			continue
		}
		stale = append(stale, d.stampStaleness(Staleness{
			Path:   artifacts[i].Path,
			Detail: firstDifference(onDisk, artifacts[i].Content),
		}))
	}
	return stale, nil
}

// normalizeNewlines rewrites CRLF to LF so that a checkout's line-ending
// convention cannot look like documentation drift.
func normalizeNewlines(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// firstDifference describes the first line where committed and generated
// content diverge, normalizing both so the line it names is a real difference
// rather than an invisible carriage return.
func firstDifference(committed, generated []byte) string {
	got := strings.Split(string(normalizeNewlines(committed)), "\n")
	want := strings.Split(string(normalizeNewlines(generated)), "\n")
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] == want[i] {
			continue
		}
		return fmt.Sprintf("line %d is %q, generated content has %q", i+1, got[i], want[i])
	}
	return fmt.Sprintf("committed content has %d lines, generated content has %d", len(got), len(want))
}

// LoadAllowlist reads the deliberate-mention allowlist from the path [Config] names.
// A missing file is an empty allowlist, not an error. A present but non-regular one
// errs instead, deliberately not folded into that branch: treating it as absent turns
// every documented token into a lint issue, with nothing naming the allowlist that
// was never read.
func (d *Docs) LoadAllowlist(repoRoot string) (Allowlist, error) {
	allowlistPath := filepath.Join(repoRoot, d.cfg.AllowlistPath)
	if isIrregular(allowlistPath) {
		return Allowlist{}, fmt.Errorf("refusing to read %s: it exists and is not a regular file", d.cfg.AllowlistPath)
	}
	// #nosec G304 -- repoRoot joined with Config.AllowlistPath, held to the same validation as every other path field, and isIrregular above refuses non-regular files.
	content, err := os.ReadFile(allowlistPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return d.ParseAllowlist("")
	case err != nil:
		return Allowlist{}, fmt.Errorf("reading %s: %w", d.cfg.AllowlistPath, err)
	}
	return d.ParseAllowlist(string(content))
}

// LintRepo checks every documented CLI reference in the repository against the
// surface: shell examples and prose in the markdown documents [Config] names plus
// every markdown file under its documentation walk root, and flag names in the Go
// comments under the trees it names. Issues come back sorted by file and line.
//
// The returned [LintScope] is what the run actually reached, not what was configured
// — they differ whenever a configured directory is missing, empty or not a regular
// file, and that difference is the point: a run that linted nothing reports no
// issues, indistinguishable from a clean repository until the scope says zero.
func (d *Docs) LintRepo(repoRoot string, s Surface, allow Allowlist) ([]Issue, LintScope, error) {
	var issues []Issue

	docs, skipped, err := d.lintedMarkdownFiles(repoRoot)
	if err != nil {
		return nil, LintScope{}, err
	}
	for _, rel := range docs {
		// #nosec G304 -- rel came from the documentation walk below repoRoot, which filepath.WalkDir selects by lstat and this package filters to regular files.
		content, readErr := os.ReadFile(filepath.Join(repoRoot, rel))
		if readErr != nil {
			return nil, LintScope{}, fmt.Errorf("reading %s: %w", rel, readErr)
		}
		issues = append(issues, d.LintMarkdown(s, rel, string(content), allow)...)
	}

	goFiles, goDirs, goSkipped, err := d.lintedGoFiles(repoRoot)
	if err != nil {
		return nil, LintScope{}, err
	}
	skipped = append(skipped, goSkipped...)
	sort.Strings(skipped)
	skipped = slices.Compact(skipped)
	for _, rel := range goFiles {
		// #nosec G304 -- same provenance as the markdown loop above: a filepath.WalkDir below repoRoot, filtered to regular files by lstat.
		src, readErr := os.ReadFile(filepath.Join(repoRoot, rel))
		if readErr != nil {
			return nil, LintScope{}, fmt.Errorf("reading %s: %w", rel, readErr)
		}
		found, lintErr := d.lintGoComments(s, rel, src, allow)
		if lintErr != nil {
			return nil, LintScope{}, lintErr
		}
		issues = append(issues, found...)
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		if issues[i].Line != issues[j].Line {
			return issues[i].Line < issues[j].Line
		}
		return issues[i].Token < issues[j].Token
	})

	scope := LintScope{
		MarkdownFiles:    docs,
		GoDirs:           goDirs,
		GoFiles:          goFiles,
		SkippedIrregular: skipped,
		Allowlist:        allow,
	}
	return issues, scope, nil
}

// lintedMarkdownFiles lists the markdown documents to check, sorted and
// deduplicated. The documentation tree is walked recursively, and compacting keeps a
// document that is both configured and under the walk root from being linted -- and
// counted -- twice.
//
// Only regular files are collected, and a skipped entry is reported rather than
// dropped so the coverage gap is visible in [LintScope]. WalkDir selects by lstat, so
// a symlink named "notes.md" matches the suffix test and the whole-file read this
// list feeds follows it: at a character device the read never stops allocating, at a
// FIFO it never returns. Configured seeds are held to the same rule -- trust attaches
// to the [Config] value, never to what it resolves to -- but are skipped rather than
// erring, because a configured document is one of a collection, unlike the single
// required inputs [Docs.LoadAllowlist] and [Docs.artifacts] read. A seed that does
// not exist at all is left in place so the read fails loudly: a configuration
// mistake, not a coverage gap.
func (d *Docs) lintedMarkdownFiles(repoRoot string) (files, skipped []string, err error) {
	for _, rel := range d.cfg.LintedMarkdown {
		if isIrregular(filepath.Join(repoRoot, rel)) {
			skipped = append(skipped, filepath.ToSlash(rel))
			continue
		}
		files = append(files, rel)
	}

	walkRoot := d.cfg.DocsWalkRoot
	walkErr := filepath.WalkDir(filepath.Join(repoRoot, walkRoot), func(path string, entry fs.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case entry.IsDir(), !strings.HasSuffix(entry.Name(), ".md"):
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return relErr
		}
		if !entry.Type().IsRegular() {
			skipped = append(skipped, filepath.ToSlash(rel))
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("walking %s: %w", walkRoot, walkErr)
	}

	sort.Strings(files)
	return slices.Compact(files), skipped, nil
}

// lintedGoFiles lists the Go files whose comments to check, sorted and deduplicated,
// alongside the directories it actually opened to find them.
//
// The directories come back beside the files because [LintRepo] reports them as
// coverage: a scope assembled from configuration would name a directory this walk
// never opened. A configured directory that is not there is left out, while one that
// is there but holds no Go files stays in -- absent coverage versus coverage that
// found nothing.
//
// The existence gate is os.Lstat, not os.Stat: os.Stat follows a symlink, so a
// symlinked root passed the gate and was reported as covered while WalkDir lstatted
// it and walked nothing. It is treated as absent and named in skipped. The walk
// collects only regular files, for the reason given on lintedMarkdownFiles.
func (d *Docs) lintedGoFiles(repoRoot string) (files, dirs, skipped []string, err error) {
	for _, dir := range d.cfg.LintedGoDirs {
		root := filepath.Join(repoRoot, dir)
		info, statErr := os.Lstat(root)
		switch {
		case errors.Is(statErr, fs.ErrNotExist):
			continue
		case statErr == nil && !info.IsDir():
			skipped = append(skipped, dir)
			continue
		}
		dirs = append(dirs, dir)
		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case entry.IsDir(), !strings.HasSuffix(entry.Name(), ".go"):
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			if !entry.Type().IsRegular() {
				skipped = append(skipped, filepath.ToSlash(rel))
				return nil
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if walkErr != nil {
			return nil, nil, nil, fmt.Errorf("walking %s: %w", dir, walkErr)
		}
	}
	sort.Strings(files)
	sort.Strings(dirs)
	return slices.Compact(files), slices.Compact(dirs), skipped, nil
}

// isIrregular reports whether path exists as something other than a regular file.
// It is the one gate every read and write in this package goes through, so a
// configured path and a discovered one are held to the same rule.
//
// The test is os.Lstat, not os.Stat, which follows a symlink and so reports on the
// target -- the thing being screened out. Closing the check-to-open window with
// syscall.O_NOFOLLOW is not portable to Windows; the residual race is accepted, the
// threat being a committed symlink a reviewer waved through, not a racing process.
//
// A path that does not exist is not irregular: collapsing the two would turn
// [Docs.Write]'s ordinary first generation into a refusal. An os.Lstat failing for
// any other reason also reads as not-irregular, handing the real error to the read
// or write that follows.
func isIrregular(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && !info.Mode().IsRegular()
}
