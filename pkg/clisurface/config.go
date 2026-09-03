package clisurface

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Repository-relative defaults. They are the values brutus generated its own
// artifacts with, so a consumer that sets only RegenerateCommand gets brutus's
// layout. Only DocsWalkRoot is a directory; the three names below it are joined
// onto whatever DocsWalkRoot resolves to.
const (
	defaultDocsWalkRoot      = "docs"
	defaultJSONName          = "cli-surface.json"
	defaultMarkdownName      = "CLI.md"
	defaultAllowlistName     = "cli-surface-allow.txt"
	defaultREADMEPath        = "README.md"
	defaultSubcommandsRegion = "cli-subcommands"
	defaultAliasesRegion     = "cli-aliases"
)

// regionNamePattern is the charset a region name must match. Region names are
// interpolated into the HTML comment markers that delimit a generated block and
// into the regular expression that finds them, so anything outside this charset
// could either terminate the comment early or change what the expression means.
// The pattern is a compile-time constant: no configuration reaches it.
var regionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Config is the settable behaviour of a Docs. Construct it as a keyed literal
// and hand it to New, which validates it and resolves every zero value to the
// default named in the field's comment; the only field with no default is
// RegenerateCommand.
//
// Every path is repository-relative and uses forward slashes on every platform,
// because these strings are both filesystem paths and content: they appear
// inside the generated artifacts, which are committed and compared byte for
// byte. A path field may not be absolute and may not contain a ".." element.
type Config struct {
	// RegenerateCommand is the command a developer should run to bring the
	// generated artifacts back in sync -- for example "make cli-docs". It is
	// required, and it is printed verbatim in drift and lint failures, so it
	// must be the command that works in the consumer's repository.
	RegenerateCommand string

	// DocsWalkRoot is the directory holding the documentation this package
	// generates and lints. It is also the default parent of JSONPath,
	// MarkdownPath and AllowlistPath, so moving it moves all three at once.
	// Defaults to "docs".
	DocsWalkRoot string

	// JSONPath is the machine-readable surface artifact.
	// Defaults to DocsWalkRoot + "/cli-surface.json".
	JSONPath string

	// MarkdownPath is the generated command reference.
	// Defaults to DocsWalkRoot + "/CLI.md".
	MarkdownPath string

	// READMEPath is the file whose generated regions are spliced in place. It
	// is deliberately not under DocsWalkRoot, since a repository's README lives
	// at its root. Defaults to "README.md".
	READMEPath string

	// AllowlistPath is the file listing flag and command names that prose may
	// mention without the linter treating them as stale.
	// Defaults to DocsWalkRoot + "/cli-surface-allow.txt".
	AllowlistPath string

	// LintedMarkdown is the set of markdown files whose prose is checked
	// against the surface. A nil slice defaults to just READMEPath; an
	// explicitly empty slice opts out of markdown linting entirely.
	LintedMarkdown []string

	// LintedGoDirs is the set of directories whose Go comments are checked
	// against the surface. A nil slice defaults to
	// []string{"cmd", "internal", "pkg"}; an explicitly empty slice opts out of
	// Go comment linting entirely. Both lint scopes may not be empty at once.
	LintedGoDirs []string

	// SubcommandsRegion names the generated subcommand table's region in
	// READMEPath. It must match ^[A-Za-z0-9_-]+$.
	// Defaults to "cli-subcommands".
	SubcommandsRegion string

	// AliasesRegion names the generated alias table's region in READMEPath. It
	// must match ^[A-Za-z0-9_-]+$. Defaults to "cli-aliases".
	AliasesRegion string
}

// New validates cfg, resolves its zero values to the defaults documented on
// each field, and returns a Docs bound to the result. The returned Docs does
// not observe later changes to cfg or to the slices cfg refers to.
//
// An invalid configuration yields a nil Docs and an error naming every field at
// fault, not just the first.
func New(cfg Config) (*Docs, error) {
	resolved := cfg.withDefaults()
	if err := resolved.validate(); err != nil {
		return nil, err
	}

	return &Docs{cfg: resolved}, nil
}

// Config reports the configuration this Docs was built with, every zero value
// already resolved to its default. The result is a copy, slice fields included:
// mutating it does not affect the Docs.
func (d *Docs) Config() Config {
	return d.cfg.clone()
}

// GeneratedPaths reports the files a successful generation writes, in the order
// a caller should present them. It is the set to stage after regenerating and
// the set a drift check reports on.
func (d *Docs) GeneratedPaths() []string {
	return []string{d.cfg.JSONPath, d.cfg.MarkdownPath, d.cfg.READMEPath}
}

// withDefaults returns cfg with every zero-valued field resolved. The three
// derived paths are joined onto the already-resolved DocsWalkRoot, so setting
// only DocsWalkRoot moves all three while an explicit path still wins. Joins go
// through path.Join, never the filepath package's join, because the result is
// artifact content as well as a path: a platform-aware join would emit
// backslashes on Windows and break byte parity with the committed artifacts.
func (cfg Config) withDefaults() Config {
	cfg.DocsWalkRoot = cmp.Or(cfg.DocsWalkRoot, defaultDocsWalkRoot)
	cfg.JSONPath = cmp.Or(cfg.JSONPath, path.Join(cfg.DocsWalkRoot, defaultJSONName))
	cfg.MarkdownPath = cmp.Or(cfg.MarkdownPath, path.Join(cfg.DocsWalkRoot, defaultMarkdownName))
	cfg.AllowlistPath = cmp.Or(cfg.AllowlistPath, path.Join(cfg.DocsWalkRoot, defaultAllowlistName))
	cfg.READMEPath = cmp.Or(cfg.READMEPath, defaultREADMEPath)
	cfg.SubcommandsRegion = cmp.Or(cfg.SubcommandsRegion, defaultSubcommandsRegion)
	cfg.AliasesRegion = cmp.Or(cfg.AliasesRegion, defaultAliasesRegion)

	// A nil slice takes the default; an explicitly empty one is a deliberate
	// opt-out and is honoured as given.
	if cfg.LintedMarkdown == nil {
		cfg.LintedMarkdown = []string{cfg.READMEPath}
	}
	if cfg.LintedGoDirs == nil {
		cfg.LintedGoDirs = []string{"cmd", "internal", "pkg"}
	}

	return cfg.clone()
}

// clone returns cfg with its slice fields copied, so that neither the caller's
// slices nor a returned Config alias the ones a Docs holds.
func (cfg Config) clone() Config {
	cfg.LintedMarkdown = slices.Clone(cfg.LintedMarkdown)
	cfg.LintedGoDirs = slices.Clone(cfg.LintedGoDirs)
	return cfg
}

// validate reports every problem with cfg as one joined error. It expects an
// already-defaulted Config: the empty-value checks below are unreachable
// through New and guard a future change to the defaulting rules instead.
func (cfg Config) validate() error {
	return errors.Join(
		validateRegenerateCommand(cfg.RegenerateCommand),
		validatePath("DocsWalkRoot", cfg.DocsWalkRoot),
		validatePath("JSONPath", cfg.JSONPath),
		validatePath("MarkdownPath", cfg.MarkdownPath),
		validatePath("READMEPath", cfg.READMEPath),
		validatePath("AllowlistPath", cfg.AllowlistPath),
		validateRegion("SubcommandsRegion", cfg.SubcommandsRegion),
		validateRegion("AliasesRegion", cfg.AliasesRegion),
		validateLintScope(cfg.LintedMarkdown, cfg.LintedGoDirs),
	)
}

// validateRegenerateCommand rejects a missing command. The value is checked
// trimmed but stored as given, so a consumer's spacing survives into the
// messages that quote it.
func validateRegenerateCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("clisurface: Config.RegenerateCommand is required")
	}

	return nil
}

// validatePath rejects a path this package must not write to or read from: an
// empty one would target the repository root, and an absolute one or one
// containing ".." would leave the repository the caller pointed us at. The
// check is on the path's shape rather than on where it resolves to, since the
// repository root is not known at construction time.
func validatePath(field, value string) error {
	slashed := filepath.ToSlash(value)

	switch {
	case value == "":
		return fmt.Errorf("clisurface: Config.%s must not be empty", field)
	case filepath.IsAbs(value) || path.IsAbs(slashed):
		return fmt.Errorf("clisurface: Config.%s must be repository-relative, got %q", field, value)
	case slices.Contains(strings.Split(slashed, "/"), ".."):
		return fmt.Errorf("clisurface: Config.%s must not contain a %q element, got %q", field, "..", value)
	}

	return nil
}

// validateRegion rejects a region name that would not survive being
// interpolated into a marker comment and into the expression that finds it.
func validateRegion(field, value string) error {
	if !regionNamePattern.MatchString(value) {
		return fmt.Errorf("clisurface: Config.%s must match %s, got %q", field, regionNamePattern, value)
	}

	return nil
}

// validateLintScope rejects a configuration that would lint nothing. Opting one
// half out is supported; opting both out would make every lint pass vacuously,
// which reads as a passing check rather than as a disabled one.
func validateLintScope(markdown, goDirs []string) error {
	if len(markdown) > 0 || len(goDirs) > 0 {
		return nil
	}

	return fmt.Errorf("clisurface: Config.LintedMarkdown and Config.LintedGoDirs are both empty, so this configuration would lint nothing")
}
