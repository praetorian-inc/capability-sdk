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

// Repository-relative defaults. They are the layout this package's original
// consumer generated its artifacts with, so a consumer that sets only
// RegenerateCommand gets that layout. Only DocsWalkRoot is a directory; the
// three names below it are joined onto whatever DocsWalkRoot resolves to.
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
// interpolated into the HTML comment markers that delimit a generated block, so
// anything outside this charset could terminate the comment early and leave the
// rest of the marker as rendered body. The pattern is a compile-time constant:
// no configuration reaches it.
var regionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Config is the settable behaviour of a Docs. Construct it as a keyed literal
// and hand it to New, which validates it and resolves every zero value to the
// default named in the field's comment; the only field with no default is
// RegenerateCommand.
//
// Every path is repository-relative and uses forward slashes on every platform,
// because these strings are both filesystem paths and content: they appear
// inside the generated artifacts, which are committed and compared byte for
// byte. A path may not be empty, may not be absolute, may not contain a ".."
// element, may not contain a backslash, and may not contain "<" or ">" -- an
// angle bracket would let a path forge or close the HTML comment markers it is
// rendered next to. That holds for every entry of LintedMarkdown and
// LintedGoDirs as well as for the scalar fields, and the entry at fault is
// named by its index. Two of JSONPath, MarkdownPath, READMEPath and
// AllowlistPath may not name the same file, since one artifact would then
// overwrite another; the comparison ignores "./", other spelling differences
// and letter case -- the last because on a case-insensitive filesystem two such
// paths are one file -- while the scalar value stored is the one you wrote.
// The two slice fields are the exception to that last clause: their entries are
// stored cleaned, so that a spelling that only looks distinct is linted once.
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
	// explicitly empty slice opts out of markdown linting entirely. Config
	// reports each entry cleaned, so "./docs/guide.md" reads back as
	// "docs/guide.md".
	LintedMarkdown []string

	// LintedGoDirs is the set of directories whose Go comments are checked
	// against the surface. A nil slice defaults to
	// []string{"cmd", "internal", "pkg"}; an explicitly empty slice opts out of
	// Go comment linting entirely. Config reports each entry cleaned, so
	// "./pkg" reads back as "pkg". Opting both lint scopes out is allowed and
	// does not mean nothing is linted: the markdown walk covers DocsWalkRoot
	// either way, and LintScope reports what a run actually reached.
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
	cfg.LintedMarkdown = cleanPathEntries(cfg.LintedMarkdown)
	cfg.LintedGoDirs = cleanPathEntries(cfg.LintedGoDirs)

	return cfg.clone()
}

// cleanPathEntries returns a new slice holding path.Clean of every non-empty
// entry, so that two spellings of one path -- "./docs/guide.md" and
// "docs/guide.md", "pkg" and "pkg/" -- become the one entry they name and the
// deduplication further down the pipeline can see them as equal. Without it the
// same file is linted twice: every issue in it is reported twice and the
// coverage sentence counts it twice.
//
// An empty entry is deliberately left as it is rather than cleaned, because
// path.Clean("") is ".", which would turn an obvious mistake into a silent walk
// of the entire repository. validate rejects it a moment later and names the
// index at fault.
func cleanPathEntries(values []string) []string {
	cleaned := make([]string, len(values))
	for i, value := range values {
		if value == "" {
			continue
		}
		cleaned[i] = path.Clean(value)
	}

	return cleaned
}

// clone returns cfg with its slice fields copied, so that neither the caller's
// slices nor a returned Config alias the ones a Docs holds.
func (cfg Config) clone() Config {
	cfg.LintedMarkdown = slices.Clone(cfg.LintedMarkdown)
	cfg.LintedGoDirs = slices.Clone(cfg.LintedGoDirs)
	return cfg
}

// validate reports every problem with cfg as one joined error. It expects an
// already-defaulted Config, so the empty-value check on a scalar path or region
// field is unreachable through New and guards a future change to the defaulting
// rules instead. The entries of the two slice-valued path fields are a separate
// case: defaulting replaces a nil slice wholesale and never inspects the entries
// of one the caller supplied, so every check below reaches those entries exactly
// as they were written -- the empty-value one included.
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

// validateRegenerateCommand rejects a missing command, and one carrying a
// character that would not survive being rendered. The value is concatenated
// raw into the HTML comment heading every generated artifact and into a
// markdown code span, so "-->" closes that comment early and leaves the rest of
// it as body text, a newline injects a line of the caller's choosing into the
// artifact, and a backtick breaks the code span. The rule is narrow on purpose:
// no plausible command line contains any of the three. The value is checked
// trimmed but stored as given, so a consumer's spacing survives into the
// messages that quote it.
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

// validatePath rejects a path this package must not write to or read from: an
// empty one would target the repository root, and an absolute one or one
// containing ".." names a location outside the repository the caller pointed us
// at. A backslash is rejected outright, because filepath.ToSlash is the identity
// on every non-Windows platform -- so without that case both halves of the
// absolute-path test below are the POSIX one, and a Windows-shaped path
// ("C:\out", "\\host\share", "\etc\passwd") passes as an ordinary
// relative name. An angle bracket is rejected because a path is artifact content
// too: MarkdownPath is interpolated raw into a region body that gets spliced
// into READMEPath, so a path spelling out an end marker corrupts the README on
// the first Write and then wedges every later Write and every drift check on a
// duplicate marker, with hand repair the only way out.
//
// The check is on the path's shape, not on where it resolves to, since the
// repository root is not known at construction time. Shape is therefore all
// this can be, and it is not containment: a path that satisfies every rule here
// still lands outside the repository if a symlink along the way points out of
// it. Write refuses to follow one for exactly that reason, and the reads this
// package does are confined to regular files for the same one.
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

// validatePathSlice applies the same rules to every entry of a slice-valued
// path field, naming the entry at fault by its index so a caller with several
// entries is told which one to fix. It returns one error per bad entry for the
// single errors.Join in validate to collect, and a nil for every good one,
// which that Join discards.
func validatePathSlice(field string, values []string) []error {
	errs := make([]error, 0, len(values))
	for i, value := range values {
		errs = append(errs, validatePath(fmt.Sprintf("%s[%d]", field, i), value))
	}

	return errs
}

// validateRegion rejects a region name that would not survive being
// interpolated into the marker comments that delimit its generated block.
func validateRegion(field, value string) error {
	if !regionNamePattern.MatchString(value) {
		return fmt.Errorf("clisurface: Config.%s must match %s, got %q", field, regionNamePattern, value)
	}

	return nil
}

// validateDistinctRegions rejects two regions that name one marker pair. Both
// generated tables would then be spliced into the same block of READMEPath, so
// whichever is written second is the only one that survives.
func validateDistinctRegions(subcommands, aliases string) error {
	if subcommands != aliases {
		return nil
	}

	return fmt.Errorf("clisurface: Config.SubcommandsRegion and Config.AliasesRegion must name different regions, both are %q", subcommands)
}

// pathField pairs a path field's name with its configured value, so a
// cross-field message can quote each side exactly as the caller wrote it.
type pathField struct {
	name  string
	value string
}

// validateDistinctPaths rejects two artifact paths that name one file. It is
// the destructive collision and it is one keystroke from a plausible config:
// MarkdownPath "README.md" renders the whole command reference over the
// consumer's hand-authored README, and because GeneratedPaths would then report
// that name twice, the list to stage and the drift report both read as though
// nothing were wrong. AllowlistPath joins the three generated paths here even
// though generation does not write it, precisely because it is hand-authored
// input: a generated artifact landing on it destroys it the same way.
//
// The comparison is on path.Clean of each value lowercased, so that
// "docs/CLI.md", "./docs/CLI.md" and "docs/cli.md" are recognised as the one
// file they are. Case is folded because on APFS and NTFS two paths differing
// only in case name one file, and the failure that follows is unrecoverable
// from inside the tool: the second artifact clobbers the first, and
// CheckArtifacts then reports permanent staleness immediately after a
// successful Write -- a red gate no correct regeneration can clear. Folding it
// on a case-sensitive filesystem too is deliberate, since a Config is portable
// content by design and the collision must be caught wherever it is authored.
//
// Only the comparison normalises: the values stay exactly as the caller wrote
// them -- because they are artifact content as well as paths -- and the message
// quotes both spellings, so a collision reached only through normalisation is
// still legible.
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
