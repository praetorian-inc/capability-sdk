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

// Repository-relative defaults. Only DocsWalkRoot is a directory; the three
// names below it are joined onto whatever DocsWalkRoot resolves to.
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
// interpolated into HTML comment markers, so anything outside this charset
// could terminate the comment early.
var regionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Config is the settable behaviour of a Docs. Construct it as a keyed literal and
// hand it to New, which validates it and resolves every zero value to the default
// named in the field's comment; only RegenerateCommand has no default.
//
// Every path is repository-relative and uses forward slashes on every platform,
// these strings being artifact content as well as paths. A path may not be empty,
// absolute, or contain a "..", a backslash, or an angle bracket, and two of
// JSONPath, MarkdownPath, READMEPath and AllowlistPath may not name the same file.
// Paths are stored cleaned; cleaning runs after validation, so a rejected path is
// quoted back in the spelling you wrote.
type Config struct {
	// RegenerateCommand is the command that brings the generated artifacts
	// back in sync -- for example "make cli-docs". Required, and printed
	// verbatim in drift and lint failures.
	RegenerateCommand string

	// DocsWalkRoot is the directory holding the documentation this package
	// generates and lints, and the default parent of JSONPath, MarkdownPath
	// and AllowlistPath. Defaults to "docs".
	DocsWalkRoot string

	// JSONPath is the machine-readable surface artifact.
	// Defaults to DocsWalkRoot + "/cli-surface.json".
	JSONPath string

	// MarkdownPath is the generated command reference.
	// Defaults to DocsWalkRoot + "/CLI.md".
	MarkdownPath string

	// READMEPath is the file whose generated regions are spliced in place.
	// Defaults to "README.md".
	READMEPath string

	// AllowlistPath lists flag and command names that prose may mention
	// without the linter treating them as stale.
	// Defaults to DocsWalkRoot + "/cli-surface-allow.txt".
	AllowlistPath string

	// LintedMarkdown is the set of markdown files whose prose is checked
	// against the surface. Nil defaults to just READMEPath; an explicitly
	// empty slice opts out.
	LintedMarkdown []string

	// LintedGoDirs is the set of directories whose Go comments are checked
	// against the surface. Nil defaults to []string{"cmd", "internal", "pkg"}; an
	// explicitly empty slice opts out. Opting both scopes out still lints the
	// markdown walk over DocsWalkRoot, and LintScope reports what was reached.
	LintedGoDirs []string

	// SubcommandsRegion names the generated subcommand table's region in
	// READMEPath. Must match ^[A-Za-z0-9_-]+$.
	// Defaults to "cli-subcommands".
	SubcommandsRegion string

	// AliasesRegion names the generated alias table's region in READMEPath.
	// Must match ^[A-Za-z0-9_-]+$. Defaults to "cli-aliases".
	AliasesRegion string
}

// New validates cfg, resolves its zero values to the documented defaults, and
// returns a Docs bound to the result. The Docs does not observe later changes to cfg
// or its slices. An invalid configuration yields a nil Docs and an error naming
// every field at fault, not just the first.
func New(cfg Config) (*Docs, error) {
	resolved := cfg.withDefaults()
	if err := resolved.validate(); err != nil {
		return nil, err
	}

	return &Docs{cfg: resolved.cleanPaths()}, nil
}

// cleanPaths returns cfg with every path field cleaned, scalar and slice alike. It
// runs after validate: cleaning first would collapse a ".." element ("cmd/.." becomes
// "."), so a path validate exists to reject would change meaning or pass. Cleaning is
// required because these fields are compared against already-cleaned paths a
// filesystem walk produced -- uncleaned, a field fails to match itself.
func (cfg Config) cleanPaths() Config {
	cfg.DocsWalkRoot = cleanScalarPath(cfg.DocsWalkRoot)
	cfg.JSONPath = cleanScalarPath(cfg.JSONPath)
	cfg.MarkdownPath = cleanScalarPath(cfg.MarkdownPath)
	cfg.READMEPath = cleanScalarPath(cfg.READMEPath)
	cfg.AllowlistPath = cleanScalarPath(cfg.AllowlistPath)
	cfg.LintedMarkdown = cleanPathEntries(cfg.LintedMarkdown)
	cfg.LintedGoDirs = cleanPathEntries(cfg.LintedGoDirs)

	return cfg
}

// cleanScalarPath is path.Clean with an empty-string carve-out: path.Clean("") is
// ".", turning an obvious mistake into a silent walk of the repository root. Nothing
// reaches it empty today -- validate has already rejected such a value.
func cleanScalarPath(value string) string {
	if value == "" {
		return ""
	}

	return path.Clean(value)
}

// cleanPathEntries returns a new slice holding cleanScalarPath of every entry,
// so that two spellings of one path ("pkg" and "pkg/") dedup downstream rather
// than linting the same file twice.
func cleanPathEntries(values []string) []string {
	cleaned := make([]string, len(values))
	for i, value := range values {
		cleaned[i] = cleanScalarPath(value)
	}

	return cleaned
}

// Config reports the configuration this Docs was built with, every zero value
// already resolved. The result is a copy, slice fields included.
func (d *Docs) Config() Config {
	return d.cfg.clone()
}

// GeneratedPaths reports the files a successful generation writes, in the order
// a caller should present them.
func (d *Docs) GeneratedPaths() []string {
	return []string{d.cfg.JSONPath, d.cfg.MarkdownPath, d.cfg.READMEPath}
}

// withDefaults returns cfg with every zero-valued field resolved. Joins go through
// path.Join, never filepath's, because the result is artifact content: a
// platform-aware join emits backslashes on Windows and breaks byte parity. It cleans
// nothing, so validate sees every path in the caller's spelling.
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

// clone returns cfg with its slice fields copied, so neither the caller's
// slices nor a returned Config alias the ones a Docs holds.
func (cfg Config) clone() Config {
	cfg.LintedMarkdown = slices.Clone(cfg.LintedMarkdown)
	cfg.LintedGoDirs = slices.Clone(cfg.LintedGoDirs)
	return cfg
}

// validate reports every problem with cfg as one joined error. It expects an
// already-defaulted Config, so the empty-value check on a scalar field guards a
// future change to the defaulting rules, not anything reachable through New. Slice
// entries are the exception: defaulting replaces a nil slice wholesale and never
// inspects supplied entries.
func (cfg Config) validate() error {
	errs := []error{
		validateRegenerateCommand(cfg.RegenerateCommand),
		validatePath("DocsWalkRoot", cfg.DocsWalkRoot),
		validatePath("JSONPath", cfg.JSONPath),
		validatePath("MarkdownPath", cfg.MarkdownPath),
		validatePath("READMEPath", cfg.READMEPath),
		validatePath("AllowlistPath", cfg.AllowlistPath),
		validateRegion("SubcommandsRegion", cfg.SubcommandsRegion),
		validateRegion("AliasesRegion", cfg.AliasesRegion),
		validateDistinctRegions(cfg.SubcommandsRegion, cfg.AliasesRegion),
	}
	errs = append(errs, validatePathSlice("LintedMarkdown", cfg.LintedMarkdown)...)
	errs = append(errs, validatePathSlice("LintedGoDirs", cfg.LintedGoDirs)...)
	errs = append(errs, validateDistinctPaths(cfg)...)

	return errors.Join(errs...)
}

// validateRegenerateCommand rejects a missing command, and one carrying a character
// that would not survive rendering: the value is concatenated raw into an HTML
// comment and a markdown code span, so "-->" closes the comment early, a newline
// injects a line, and a backtick breaks the span.
func validateRegenerateCommand(command string) error {
	switch {
	case strings.TrimSpace(command) == "":
		return errors.New("clisurface: Config.RegenerateCommand is required")
	case strings.ContainsAny(command, "\n\r`"):
		return fmt.Errorf("clisurface: Config.RegenerateCommand must be a single line and must not contain a backtick, got %q", command)
	case strings.Contains(command, "-->"):
		return fmt.Errorf("clisurface: Config.RegenerateCommand must not contain %q, got %q", "-->", command)
	}

	return nil
}

// validatePath rejects a path this package must not write to or read from. A
// backslash is rejected outright because filepath.ToSlash is the identity off
// Windows, so without that case a Windows-shaped path ("C:\out", "\\host\share")
// passes as a relative name. An angle bracket is rejected because MarkdownPath is
// interpolated raw into a spliced region body, so a path spelling an end marker
// corrupts the README and wedges every later Write.
//
// This rules on shape, not on where the path resolves to, and is not containment: a
// symlink along an otherwise valid path still lands outside the repository, which is
// why Write refuses to follow one.
func validatePath(field, value string) error {
	slashed := filepath.ToSlash(value)

	switch {
	case value == "":
		return fmt.Errorf("clisurface: Config.%s must not be empty", field)
	case strings.Contains(value, `\`):
		return fmt.Errorf("clisurface: Config.%s must use forward slashes on every platform, got %q", field, value)
	case filepath.IsAbs(value) || path.IsAbs(slashed):
		return fmt.Errorf("clisurface: Config.%s must be repository-relative, got %q", field, value)
	case slices.Contains(strings.Split(slashed, "/"), ".."):
		return fmt.Errorf("clisurface: Config.%s must not contain a %q element, got %q", field, "..", value)
	case strings.ContainsAny(value, "<>"):
		return fmt.Errorf("clisurface: Config.%s must not contain %q or %q, got %q", field, "<", ">", value)
	}

	return nil
}

// validatePathSlice applies validatePath to every entry, naming the entry at
// fault by its index. Nils for good entries are discarded by validate's Join.
func validatePathSlice(field string, values []string) []error {
	errs := make([]error, 0, len(values))
	for i, value := range values {
		errs = append(errs, validatePath(fmt.Sprintf("%s[%d]", field, i), value))
	}

	return errs
}

// validateRegion rejects a region name that would not survive interpolation
// into the marker comments delimiting its generated block.
func validateRegion(field, value string) error {
	if !regionNamePattern.MatchString(value) {
		return fmt.Errorf("clisurface: Config.%s must match %s, got %q", field, regionNamePattern, value)
	}

	return nil
}

// validateDistinctRegions rejects two regions naming one marker pair: both
// tables would splice into the same block, and only the second would survive.
func validateDistinctRegions(subcommands, aliases string) error {
	if subcommands != aliases {
		return nil
	}

	return fmt.Errorf("clisurface: Config.SubcommandsRegion and Config.AliasesRegion must name different regions, both are %q", subcommands)
}

// pathField pairs a path field's name with its configured value, so a
// cross-field message can quote each side as the caller wrote it.
type pathField struct {
	name  string
	value string
}

// validateDistinctPaths rejects two artifact paths naming one file -- the
// destructive collision, one keystroke from a plausible config: MarkdownPath
// "README.md" renders the command reference over the hand-authored README.
// AllowlistPath joins the generated paths here because it is hand-authored input a
// generated artifact would destroy the same way.
//
// Comparison folds case as well as cleaning: on APFS and NTFS two paths differing
// only in case name one file, and folding on a case-sensitive filesystem too is
// deliberate, a Config being portable content. Folding is the comparison's alone --
// New stores paths cleaned but never lowercased -- and this runs before that
// cleaning, so messages quote what the caller wrote.
func validateDistinctPaths(cfg Config) []error {
	fields := []pathField{
		{"JSONPath", cfg.JSONPath},
		{"MarkdownPath", cfg.MarkdownPath},
		{"READMEPath", cfg.READMEPath},
		{"AllowlistPath", cfg.AllowlistPath},
	}

	var errs []error
	firstByPath := make(map[string]pathField, len(fields))
	for _, field := range fields {
		cleaned := strings.ToLower(path.Clean(field.value))
		if first, taken := firstByPath[cleaned]; taken {
			errs = append(errs, fmt.Errorf("clisurface: Config.%s (%q) and Config.%s (%q) must name different files",
				first.name, first.value, field.name, field.value))
			continue
		}
		firstByPath[cleaned] = field
	}

	return errs
}
