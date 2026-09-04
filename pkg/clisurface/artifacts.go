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

// FindRepoRoot walks up from start until it finds the directory holding go.mod.
// A drift gate usually runs as a test, whose working directory is the package
// directory, so it needs the repository root to read and write the
// repo-relative artifacts [Config] names.
//
// It takes no [Docs] receiver because it reads no configuration: where a module
// begins is a property of the checkout, not of how a caller configured its
// documentation.
//
// Only a regular go.mod counts. os.Stat would report neither the entry's type
// nor whether it is a symlink, so a directory named go.mod, or one symlinked out
// of the tree, would win over the real module root above it -- and the root this
// returns decides where every artifact is written and which trees are linted, so
// choosing it wrongly relocates the entire run rather than failing.
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
// its current on-disk content, so the hand-written parts of it are preserved.
//
// It is unexported because the two things a caller wants to do with the result
// are already methods: write it ([Docs.Write]) or compare it
// ([Docs.CheckArtifacts]). Exporting the intermediate would publish a slice of
// path-and-bytes pairs whose only contract is that those two methods agree
// about it.
func (d *Docs) artifacts(repoRoot string, s Surface) ([]artifact, error) {
	jsonBytes, err := d.renderJSON(s)
	if err != nil {
		return nil, err
	}

	readmePath := filepath.Join(repoRoot, d.cfg.READMEPath)
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

// Write writes every generated artifact. This is the update path; the drift
// gate itself must never call it.
//
// An artifact path that already exists as something other than a regular file
// is refused rather than written through. [Config] validates the shape of a
// path, but a shape cannot express where a path resolves to: with the
// repository's own docs/CLI.md replaced by a symlink, an ordinary regeneration
// would overwrite whatever it pointed at -- outside the repository, at the
// target's own mode, leaving nothing behind to notice. os.Lstat is the portable
// way to see that; syscall.O_NOFOLLOW is not available on Windows.
//
// The refusal is a returned error and never a skip. A skipped artifact would
// leave [Docs.CheckArtifacts] reporting drift that no correct regeneration
// could ever clear, which is the same unrecoverable red gate by a quieter route.
func (d *Docs) Write(repoRoot string, s Surface) error {
	artifacts, err := d.artifacts(repoRoot, s)
	if err != nil {
		return err
	}
	for i := range artifacts {
		path := filepath.Join(repoRoot, artifacts[i].Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", artifacts[i].Path, err)
		}
		if info, lstatErr := os.Lstat(path); lstatErr == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to write %s: it already exists and is not a regular file", artifacts[i].Path)
		}
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

	// regenerateCommand is the resolved [Config] value [Staleness.String] needs
	// in order to tell the reader how to fix the drift. The producing method
	// stamps it in (see stampStaleness), which is what lets String keep its
	// exact wording without taking a receiver or a second argument. The cost is
	// that a Staleness a caller builds itself renders without it: String stays
	// safe on the zero value -- naming no command -- rather than panicking.
	regenerateCommand string
}

// stampStaleness records the resolved [Config] value [Staleness.String] needs on
// one staleness. Every method that produces staleness passes each one through
// here, so what a rendered line tells the reader to run is what its own Docs was
// configured with, and never a package-level default the consumer never chose.
func (d *Docs) stampStaleness(s Staleness) Staleness {
	s.regenerateCommand = d.cfg.RegenerateCommand
	return s
}

// String renders the staleness as one actionable line.
func (s Staleness) String() string {
	return fmt.Sprintf("%s is stale: %s. Regenerate it with '%s'", s.Path, s.Detail, s.regenerateCommand)
}

// CheckArtifacts compares the committed artifacts against what the surface
// renders, without writing anything.
//
// Line endings are normalized before comparing. A repository that carries no
// .gitattributes leaves a contributor with core.autocrlf=true holding CRLF on
// disk while the renderers emit LF -- comparing raw bytes would report every
// generated file as stale on Windows, which is exactly the unexplained friction
// that gets a gate disabled.
func (d *Docs) CheckArtifacts(repoRoot string, s Surface) ([]Staleness, error) {
	artifacts, err := d.artifacts(repoRoot, s)
	if err != nil {
		return nil, err
	}

	var stale []Staleness
	for i := range artifacts {
		path := filepath.Join(repoRoot, artifacts[i].Path)
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
// content diverge. Both sides are normalized first, so the line it names is a
// real difference rather than an invisible carriage return.
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

// LoadAllowlist reads the deliberate-mention allowlist from the path [Config]
// names. A missing file is an empty allowlist, not an error.
func (d *Docs) LoadAllowlist(repoRoot string) (Allowlist, error) {
	content, err := os.ReadFile(filepath.Join(repoRoot, d.cfg.AllowlistPath))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return d.ParseAllowlist("")
	case err != nil:
		return Allowlist{}, fmt.Errorf("reading %s: %w", d.cfg.AllowlistPath, err)
	}
	return d.ParseAllowlist(string(content))
}

// LintRepo checks every documented CLI reference in the repository against the
// surface: shell examples and prose in the markdown documents [Config] names
// plus every markdown file under its documentation walk root, and flag names in
// the Go comments under the trees it names. Issues come back sorted by file and
// line.
//
// The returned [LintScope] is what the walk actually reached, not what was
// configured. The two differ whenever a configured directory is missing or
// empty, or an entry matched by name turned out not to be a regular file, and
// that difference is the whole point: a run that linted nothing reports no
// issues, which is indistinguishable from a clean repository until the scope
// says zero files.
//
// The trees are named by configuration rather than spelled out in this comment,
// because the last time this comment listed them it went stale the moment
// another one was added -- in a gate whose whole job is catching that.
func (d *Docs) LintRepo(repoRoot string, s Surface, allow Allowlist) ([]Issue, LintScope, error) {
	var issues []Issue

	docs, skipped, err := d.lintedMarkdownFiles(repoRoot)
	if err != nil {
		return nil, LintScope{}, err
	}
	for _, rel := range docs {
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
// deduplicated.
//
// The documentation tree is walked recursively: a document that names a removed
// flag escapes the gate just as thoroughly from a nested directory as from the
// top of the tree, and a check with a silent blind spot is worse than one whose
// reach is obvious.
//
// Deduplication is what makes that reach safe to widen. A configured document
// that also falls under the walk root -- a README inside the documentation
// tree, say -- is named twice, and linting it twice would emit each of its
// issues verbatim twice and double-count the coverage sentence. Compacting the
// sorted list handles a duplicate from any source, rather than special-casing
// the one overlap that is easy to picture.
// Only regular files are collected. filepath.WalkDir selects entries by lstat,
// so a symlink named "notes.md" matches the suffix test above just as a document
// does -- and the whole-file read this list feeds does not lstat anything, so it
// follows the link wherever it goes. That is unbounded rather than merely wrong:
// pointed at a character device the read never stops allocating, and pointed at
// a FIFO it never returns at all, both reachable from a documentation-only
// change that needs no special approval to run a gate. A skipped entry is
// returned rather than dropped, because a silent gap in coverage is the very
// thing [LintScope] exists to make visible.
func (d *Docs) lintedMarkdownFiles(repoRoot string) (files, skipped []string, err error) {
	files = append([]string(nil), d.cfg.LintedMarkdown...)

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

// lintedGoFiles lists the Go files whose comments to check, sorted and
// deduplicated, alongside the directories it actually opened to find them.
//
// The files are compacted for the same reason the markdown documents are:
// nothing stops a consumer configuring a directory and a directory beneath it,
// and a file both trees contain is still one file with one set of issues.
//
// The directories come back beside the files because [LintRepo] reports them as
// coverage: a scope assembled from configuration instead would name a directory
// this walk never opened. A configured directory that is not there is therefore
// left out, while one that is there but holds no Go files stays in, contributing
// zero files -- the first is absent coverage, the second is coverage that found
// nothing, and only the second is a fact about the repository. They are sorted
// and compacted for the same reason the files are: nothing rejects a repeated
// entry in the configuration, and a directory named twice was still walked once.
//
// The existence gate is os.Lstat, not os.Stat, because os.Stat follows a
// symlink: a symlinked root passed the gate and was reported as covered, while
// WalkDir lstatted it, found a non-directory and walked nothing -- a scope
// claiming a directory over zero files, which is exactly the false assurance
// this pair of return values exists to prevent. A symlinked root is therefore
// treated as absent, and named in skipped so that the absence is louder than a
// directory that was simply never created. The walk itself collects only regular
// files, for the reason given on lintedMarkdownFiles.
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
