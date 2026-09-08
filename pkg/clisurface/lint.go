package clisurface

import (
	"fmt"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// usePlaceholders are the Use-string fields describing an invocation's shape rather
// than sketching a positional, so hasArgSketch must not read one as an argument.
// Reading "[command]" as an argument was a measured false negative: with "config
// [command]" runnable over a child "show", "tool config shwo" drew no finding.
// Membership is case-folded -- the hand-written spellings carry no lowercase
// guarantee.
var usePlaceholders = map[string]bool{
	"[flags]":      true,
	"[command]":    true,
	"<command>":    true,
	"[subcommand]": true,
	"<subcommand>": true,
}

// longFlagPattern matches a long flag token in prose or a Go comment; group 2 is
// the token. The leading group requires the dashes to start a word, so "// -----"
// rules, a "--" separator and "dash--dash" cannot look like flags.
var longFlagPattern = regexp.MustCompile(`(^|[^A-Za-z0-9_])(--[a-zA-Z0-9][a-zA-Z0-9._-]*)`)

// backtickPattern matches an inline code span on a single line.
var backtickPattern = regexp.MustCompile("`[^`\n]+`")

// Issue is one documentation reference to a flag or subcommand that the CLI
// does not accept.
type Issue struct {
	// File is the repo-relative file the reference appears in.
	File string
	// Line is the 1-based line the reference appears on.
	Line int
	// Token is the offending token exactly as written, dashes included. No
	// example: this package's own comments are linted, so quoting a real removed
	// flag would need an allowlist entry suppressing that name everywhere.
	Token string
	// Command is the command the token was checked against, empty when the
	// token was checked against the whole surface (prose and Go comments).
	Command string
	// Reason says what is wrong.
	Reason string
	// Suggestion is the nearest real flag or subcommand, empty when nothing is
	// close.
	Suggestion string
	// Subcommand reports whether Token is a subcommand name rather than a flag.
	// The allowlist holds flag tokens only (see [Docs.ParseAllowlist]), so
	// offering it for a subcommand sends the reader to write a rejected entry.
	Subcommand bool

	// The four fields below are the resolved [Config] values [Issue.String] needs
	// to name a path or a command, stamped in by the producing method (see stamp)
	// so String needs no receiver. A caller-built Issue renders without them.
	jsonPath          string
	markdownPath      string
	allowlistPath     string
	regenerateCommand string
}

// stamp records the resolved [Config] values [Issue.String] needs, so a
// rendered issue names what its own Docs was configured with rather than a
// package-level default the consumer never chose.
func (d *Docs) stamp(i Issue) Issue {
	i.jsonPath = d.cfg.JSONPath
	i.markdownPath = d.cfg.MarkdownPath
	i.allowlistPath = d.cfg.AllowlistPath
	i.regenerateCommand = d.cfg.RegenerateCommand
	return i
}

// String renders the issue as one actionable line.
func (i Issue) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:%d: %s %s", i.File, i.Line, i.Token, i.Reason)
	if i.Command != "" {
		// Every command-scoped reason ends in a preposition, so the command
		// reads as part of the sentence: `--exec is not a flag of "brutus logon"`.
		fmt.Fprintf(&b, " %s", strconv.Quote(i.Command))
	}
	if i.Suggestion != "" {
		label := "nearest real flag"
		if i.Subcommand {
			label = "nearest subcommand"
		}
		fmt.Fprintf(&b, "; %s: %s", label, i.Suggestion)
	}
	// An issue inside a generated file is a symptom of a stale artifact, not
	// something to hand-edit or allowlist: say so, or the reader "fixes" a file
	// the next regeneration overwrites.
	if i.whollyGenerated() {
		fmt.Fprintf(&b, ". %s is generated: regenerate it with '%s' rather than editing it",
			i.File, i.regenerateCommand)
		return b.String()
	}
	if i.Subcommand {
		fmt.Fprintf(&b, ". Fix the documentation: %s holds flag tokens only", i.allowlistPath)
		return b.String()
	}
	fmt.Fprintf(&b, ". Fix the documentation, or add %s to %s with a '#' reason if the mention is deliberate",
		i.Token, i.allowlistPath)
	return b.String()
}

// whollyGenerated reports whether every line of the issue's file is generated. The
// README is excluded: only two of its regions are. The empty-File guard keeps an
// unstamped issue out, where every field is "" and File would match jsonPath.
func (i Issue) whollyGenerated() bool {
	return i.File != "" && (i.File == i.jsonPath || i.File == i.markdownPath)
}

// Allowlist holds deliberately documented tokens and why each is allowed.
type Allowlist struct {
	reasons map[string]string
}

// ParseAllowlist reads an allowlist file. Every entry is one token ("--<flag>" or
// "-<x>") followed by a '#' comment giving the reason; blank lines and whole-line
// comments are ignored. The reason is mandatory -- an unexplained exception is how a
// stale reference survives forever. A parse error names [Config.AllowlistPath].
func (d *Docs) ParseAllowlist(content string) (Allowlist, error) {
	out := Allowlist{reasons: map[string]string{}}
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, reason, found := strings.Cut(line, "#")
		entry = strings.TrimSpace(entry)
		reason = strings.TrimSpace(reason)
		switch {
		case !strings.HasPrefix(entry, "-"):
			return Allowlist{}, fmt.Errorf("%s:%d: entry %q must start with '-'", d.cfg.AllowlistPath, i+1, entry)
		case !found || reason == "":
			return Allowlist{}, fmt.Errorf("%s:%d: entry %q needs a '# reason' explaining why it is allowed", d.cfg.AllowlistPath, i+1, entry)
		}
		out.reasons[entry] = reason
	}
	return out, nil
}

// Allows reports whether the token is allowlisted.
func (a Allowlist) Allows(entry string) bool {
	_, ok := a.reasons[entry]
	return ok
}

// Entries returns the allowlisted tokens in sorted order.
func (a Allowlist) Entries() []string {
	out := make([]string, 0, len(a.reasons))
	for entry := range a.reasons {
		out = append(out, entry)
	}
	sort.Strings(out)
	return out
}

// LintMarkdown checks one markdown document against the surface.
//
// Fenced code blocks are parsed as shell: continuations joined, pipelines split, and
// only segments whose argv[0] is the CLI binary checked — every other tool's flags
// are ignored, keeping the false-positive rate at zero. Prose outside fences is
// checked more loosely: backticked long-flag tokens only, against the union of every
// flag in the tree, because prose rarely says which command it means. So an
// invocation the binary does not lead ("sudo brutus …") is skipped — recognizing
// prefixes one at a time trades a guarantee for a list that is never finished.
func (d *Docs) LintMarkdown(s Surface, file, content string, allow Allowlist) []Issue {
	var issues []Issue

	var (
		inFence    bool
		fence      string
		pending    string
		pendingAt  int
		flushFence = func() {
			if pending == "" {
				return
			}
			issues = append(issues, lintShellLine(s, file, pendingAt, pending, allow)...)
			pending = ""
		}
	)

	for i, raw := range strings.Split(content, "\n") {
		lineNo := i + 1
		trimmed := strings.TrimSpace(raw)

		if !inFence {
			if delim := fenceDelimiter(trimmed); delim != "" {
				inFence, fence = true, delim
				continue
			}
			issues = append(issues, lintProseLine(s, file, lineNo, raw, allow)...)
			continue
		}

		if isFenceClose(trimmed, fence) {
			flushFence()
			inFence, fence = false, ""
			continue
		}

		body := strings.TrimRight(raw, " \t")
		if pending == "" {
			pendingAt = lineNo
		}
		if strings.HasSuffix(body, `\`) {
			pending += strings.TrimSuffix(body, `\`) + " "
			continue
		}
		pending += body
		flushFence()
	}
	flushFence()

	for k := range issues {
		issues[k] = d.stamp(issues[k])
	}
	return issues
}

// fenceDelimiter returns the fence a line opens a code block with, or "". It
// returns the whole run: a block opened with four backticks may contain a
// three-backtick line as content, and closing early inverts the fence state for the
// rest of the document.
func fenceDelimiter(trimmed string) string {
	for _, marker := range []byte{'`', '~'} {
		n := 0
		for n < len(trimmed) && trimmed[n] == marker {
			n++
		}
		if n >= 3 {
			return trimmed[:n]
		}
	}
	return ""
}

// isFenceClose reports whether the line closes the open fence: the same marker, at
// least as long as the opener, and nothing else on the line.
func isFenceClose(trimmed, fence string) bool {
	if len(trimmed) < len(fence) || !strings.HasPrefix(trimmed, fence) {
		return false
	}
	return strings.Trim(trimmed, fence[:1]) == ""
}

// flagName strips a long-flag token down to its name. Only a trailing "." can survive
// the pattern -- its character class does not include the other sentence punctuation --
// and prose ending a sentence on a flag is common enough to be worth trimming.
func flagName(tok string) string {
	return strings.TrimRight(strings.TrimPrefix(tok, "--"), ".")
}

// lintProseLine checks the backticked long-flag tokens of one prose line
// against the union of every flag in the tree.
func lintProseLine(s Surface, file string, line int, raw string, allow Allowlist) []Issue {
	var issues []Issue
	known := vocabulary(s)
	for _, span := range backtickPattern.FindAllString(raw, -1) {
		for _, tok := range longFlagTokens(span) {
			name := flagName(tok)
			if allow.Allows("--"+name) || contains(known, name) {
				continue
			}
			issues = append(issues, Issue{
				File:       file,
				Line:       line,
				Token:      tok,
				Reason:     "is not a flag of any command in the CLI",
				Suggestion: nearest(name, known),
			})
		}
	}
	return issues
}

// lintShellLine checks one logical shell line from a fenced code block.
func lintShellLine(s Surface, file string, line int, text string, allow Allowlist) []Issue {
	var issues []Issue
	root := s.Root()
	for _, argv := range shellSegments(text) {
		if len(argv) == 0 || baseName(argv[0]) != root {
			continue
		}
		issues = append(issues, lintInvocation(s, file, line, argv, allow)...)
	}
	return issues
}

// lintInvocation checks one "brutus ..." invocation in the two stages cobra works in:
// resolve the command, stepping over flags and the values they consume, then validate
// every flag against the command finally resolved. Cobra parses the whole argv against
// that command's flag set, so a flag's position relative to the subcommand does not
// change whether it is accepted; judging each flag against whichever command was
// resolved when it was read errs both ways.
//
// Values are stepped over using the command resolved so far, as cobra does: a
// non-boolean flag takes the next argument, a value-taking shorthand takes the rest of
// its token ("-oresults.json") or the next argument, and "--" ends flag parsing.
// Reading a value as a flag reports its characters as nonexistent shorthands.
func lintInvocation(s Surface, file string, line int, argv []string, allow Allowlist) []Issue {
	cmd, ok := s.Command(s.Root())
	if !ok {
		return nil
	}

	var (
		issues []Issue
		flags  []string
	)

	// resolving stays true across flags and goes false at the first positional
	// that is not a subcommand: from there argv holds this command's arguments,
	// and one that happens to spell a subcommand name is not one.
	resolving := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}

		switch {
		case arg == "--":
			// pflag stops parsing here: everything after is positional,
			// however much it looks like a flag.
			i = len(argv)
		case arg == "-":
			// A bare "-" is a positional, conventionally stdin.
			resolving = false
		case strings.HasPrefix(arg, "--"):
			flags = append(flags, arg)
			if longFlagTakesNext(cmd, arg, next) {
				i++
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			flags = append(flags, arg)
			if shortFlagTakesNext(cmd, arg, next) {
				i++
			}
		case resolving:
			child := resolveChild(s, cmd.Path, arg)
			if child != nil {
				cmd = child
				break
			}
			// Not a subcommand, so from here argv holds this command's
			// arguments -- true whether or not the token is worth reporting, so
			// resolving stops on every path out. Left on, a later argument
			// spelling a real subcommand name would advance cmd.
			if reportsBogusSubcommand(s, cmd) {
				issues = append(issues, Issue{
					File: file, Line: line, Token: arg, Command: cmd.Path,
					Reason:     "is not a subcommand of",
					Suggestion: nearestCommand(s, cmd.Path, arg),
					Subcommand: true,
				})
			}
			resolving = false
		}
	}

	for _, arg := range flags {
		if strings.HasPrefix(arg, "--") {
			issues = append(issues, checkLongFlag(s, cmd, file, line, arg, allow)...)
			continue
		}
		issues = append(issues, checkShortFlags(cmd, file, line, arg, allow)...)
	}
	return issues
}

// longFlagTakesNext reports whether the argument after a "--<name>" token is that
// flag's value. A "--<name>=<value>" token carries its own; otherwise any
// non-boolean flag takes the next argument. An undeclared flag is guessed from
// shape, so one unknown flag does not also get its value read as a bogus
// subcommand.
func longFlagTakesNext(cmd *Command, arg, next string) bool {
	name, _, carriesValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	if next == "" || carriesValue || name == "" || name == HelpFlag {
		return false
	}
	if flag, known := cmd.Flag(name); known {
		return flag.Type != "bool"
	}
	return !strings.HasPrefix(next, "-")
}

// shortFlagTakesNext reports whether the argument after a "-x" token or "-xyz"
// cluster is a value of that cluster. pflag clusters booleans freely, and the first
// value-taking flag swallows the rest of the token ("-oresults.json") or, when the
// token ends there, the next argument.
func shortFlagTakesNext(cmd *Command, arg, next string) bool {
	if next == "" {
		return false
	}
	cluster := []rune(strings.TrimPrefix(arg, "-"))
	for i := 0; i < len(cluster); i++ {
		r := cluster[i]
		if !isShorthandRune(r) {
			return false
		}
		if r == 'h' {
			continue
		}
		flag, ok := cmd.FlagByShorthand(string(r))
		switch {
		case !ok:
			// Unknown, so whether the rest of the token is more shorthands or a
			// value is unknowable. Reported by checkShortFlags; guessing here
			// would only move the damage.
			return false
		case flag.Type == "bool":
			continue
		}
		return strings.TrimPrefix(string(cluster[i+1:]), "=") == ""
	}
	return false
}

// checkLongFlag validates a "--<name>" or "--<name>=<value>" token against cmd.
func checkLongFlag(s Surface, cmd *Command, file string, line int, arg string, allow Allowlist) []Issue {
	name, _, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	written := "--" + name
	if name == "" || name == HelpFlag || allow.Allows(written) {
		return nil
	}

	flag, ok := cmd.Flag(name)
	switch {
	case ok && flag.Rejected:
		// No edit-distance suggestion here: the command's own rejection
		// message already names the flag to use instead.
		return []Issue{{
			File: file, Line: line, Token: written, Command: cmd.Path,
			Reason: "is rejected by this command: " + flag.RejectedReason + ", so it is not usable on",
		}}
	case ok:
		return nil
	}

	reason := "is not a flag of"
	if contains(s.FlagNames(), name) {
		reason = "exists on other commands but not on"
	}
	return []Issue{{
		File: file, Line: line, Token: written, Command: cmd.Path,
		Reason:     reason,
		Suggestion: nearest(name, usableFlagNames(cmd)),
	}}
}

// checkShortFlags validates a "-x" token or "-xyz" cluster against cmd, reading the
// cluster the way pflag does (see shortFlagTakesNext): scanning a flag's value as
// more shorthands turns "-oresults.json" into six invented flags.
func checkShortFlags(cmd *Command, file string, line int, arg string, allow Allowlist) []Issue {
	var issues []Issue

	cluster := []rune(strings.TrimPrefix(arg, "-"))
	for i := 0; i < len(cluster); i++ {
		r := cluster[i]
		if !isShorthandRune(r) {
			// Not a shorthand, so this token is a value rather than a cluster.
			return issues
		}

		written := "-" + string(r)
		// -h is cobra's help shorthand, present on every command.
		if r == 'h' || allow.Allows(written) {
			continue
		}

		flag, ok := cmd.FlagByShorthand(string(r))
		if !ok {
			issues = append(issues, Issue{
				File: file, Line: line, Token: written, Command: cmd.Path,
				Reason: "is not a shorthand flag of",
			})
			// Stop here. Without knowing whether this shorthand takes a value
			// there is no way to tell whether the rest of the token is more
			// shorthands or that value, and guessing invents findings.
			return issues
		}
		if flag.Rejected {
			issues = append(issues, Issue{
				File: file, Line: line, Token: written, Command: cmd.Path,
				Reason: "is rejected by this command: " + flag.RejectedReason + ", so it is not usable on",
			})
		}
		if flag.Type != "bool" {
			// A value-taking shorthand ends the cluster.
			return issues
		}
	}
	return issues
}

// isShorthandRune reports whether r can be a pflag shorthand. Anything else
// (a digit sign, a slash, a dot) means the token is a value, not a flag
// cluster, and the rest of it must not be validated.
func isShorthandRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// reportsBogusSubcommand reports whether a positional that is not one of cmd's
// children is worth reporting as a misspelled subcommand. cmd must have children, or
// nothing was misspelled, and must not take a positional itself -- for a command that
// both dispatches and accepts an argument, a non-child positional is as likely to be
// that argument as a typo. Two limitations follow: a real typo under a parent that
// both runs and sketches an argument goes unreported, and a command taking a
// positional it does not sketch in Use is still reported.
func reportsBogusSubcommand(s Surface, cmd *Command) bool {
	return len(s.Children(cmd.Path)) > 0 && !takesPositional(cmd)
}

// takesPositional reports whether cmd's own declared interface says it accepts a
// positional. The surface does not carry cobra's Args validator -- the authoritative
// answer -- because adding it would change the JSON schema and invalidate every
// consumer's golden, so this needs both signals the surface has. Runnable alone is not
// enough: a root with a RunE and subcommands is the common cobra shape, and treating
// it as "takes an argument" would suppress mistyped subcommand reports at the top
// level of nearly every CLI. The second signal is the Use string -- see hasArgSketch.
func takesPositional(cmd *Command) bool {
	return cmd.Runnable && hasArgSketch(cmd.Use)
}

// hasArgSketch reports whether a cobra Use string sketches a positional argument after
// the command name. The recognized shapes, exhaustively: the first field is the
// command's own name and is dropped; a field beginning with "-" is a flag; a field in
// usePlaceholders describes the invocation's shape; every other non-empty field is an
// argument sketch whatever its punctuation, so "[owner/repo]", "<domain>", "TARGET" and
// a bare "path" all count. False is the deliberate default for a Use string this does
// not understand, because false means the linter keeps reporting.
func hasArgSketch(use string) bool {
	fields := strings.Fields(use)
	if len(fields) < 2 {
		return false
	}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") || usePlaceholders[strings.ToLower(f)] {
			continue
		}
		return true
	}
	return false
}

// resolveChild resolves one path segment to a direct subcommand of path, by
// name or by alias.
func resolveChild(s Surface, path, segment string) *Command {
	if c, ok := s.Command(path + " " + segment); ok {
		return c
	}
	for _, c := range s.Children(path) {
		if contains(c.Aliases, segment) {
			return c
		}
	}
	return nil
}

// vocabulary is every flag name documentation may name without saying which
// command it means: the union of the tree's flags plus cobra's help flag.
func vocabulary(s Surface) []string {
	return append(s.FlagNames(), HelpFlag)
}

// usableFlagNames lists the flags actually usable on cmd.
func usableFlagNames(cmd *Command) []string {
	out := make([]string, 0, len(cmd.Flags))
	for i := range cmd.Flags {
		if !cmd.Flags[i].Rejected {
			out = append(out, cmd.Flags[i].Name)
		}
	}
	return out
}

// lintGoComments checks every long-flag token in one Go file's comments, so a
// renamed flag cannot survive where no compiler and no test reads. Unexported
// because linting a repository is the supported entry point.
func (d *Docs) lintGoComments(s Surface, file string, src []byte, allow Allowlist) ([]Issue, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}

	known := vocabulary(s)
	var issues []Issue
	for _, group := range parsed.Comments {
		for _, comment := range group.List {
			line := fset.Position(comment.Slash).Line
			for _, tok := range longFlagTokens(comment.Text) {
				name := flagName(tok)
				if name == "" || allow.Allows("--"+name) || contains(known, name) {
					continue
				}
				issues = append(issues, Issue{
					File:       file,
					Line:       line,
					Token:      "--" + name,
					Reason:     "is named in a comment but is not a flag of any command in the CLI",
					Suggestion: nearest(name, known),
				})
			}
		}
	}
	for k := range issues {
		issues[k] = d.stamp(issues[k])
	}
	return issues, nil
}

// LintScope records what a lint run actually reached, so [LintReport] can state its own
// coverage. A scope that matched nothing is the failure mode it exists for: a missing or
// symlinked walk root lints zero files, and "no issues" alone is indistinguishable from
// a clean repository.
type LintScope struct {
	// MarkdownFiles are the repo-relative markdown documents that were linted.
	MarkdownFiles []string
	// GoDirs are the repo-relative directories that were walked for Go files.
	GoDirs []string
	// GoFiles are the repo-relative Go files found under GoDirs and linted.
	GoFiles []string
	// SkippedIrregular are the repo-relative entries the run declined to read
	// because they are not regular files -- a symlink, device, FIFO or socket --
	// plus any configured Go directory that is not a directory. Reading such an
	// entry whole is unbounded or never-returning, and following one leaves the
	// repository. Entries are listed rather than dropped: an unexplained gap
	// reads as a clean repo.
	SkippedIrregular []string
	// Allowlist is the allowlist the run suppressed tokens with.
	Allowlist Allowlist
}

// LintReport renders lint issues as a failure message ending with the scope the run
// covered. The scope line is appended rather than woven in, so a caller matching on
// issue lines is unaffected. It reports the allowlist size too: a suppressed token is
// invisible in the issue list, so a reader could not otherwise tell a clean repository
// from a silenced one.
func LintReport(issues []Issue, scope LintScope) string {
	var b strings.Builder
	fmt.Fprintf(&b, "documentation references %d CLI flag(s) or subcommand(s) that do not exist:\n\n", len(issues))
	for i := range issues {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, issues[i].String())
	}
	fmt.Fprintf(&b, "\nLinted %d markdown file(s) [%s] and %d Go file(s) under %d Go dir(s) [%s], with %d token(s) allowlisted.\n",
		len(scope.MarkdownFiles), scopeNames(scope.MarkdownFiles),
		len(scope.GoFiles), len(scope.GoDirs), scopeNames(scope.GoDirs),
		len(scope.Allowlist.Entries()))
	if len(scope.SkippedIrregular) > 0 {
		fmt.Fprintf(&b, "Skipped %d entr(y/ies) that are not regular files [%s]; nothing outside a regular file is read.\n",
			len(scope.SkippedIrregular), scopeNames(scope.SkippedIrregular))
	}
	return strings.TrimRight(b.String(), "\n")
}

// scopeNames renders one scope list for the report, naming the empty list
// rather than printing an empty bracket the reader has to interpret.
func scopeNames(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// --- shell tokenising -------------------------------------------------------

// shellSegments splits one logical shell line into pipeline segments of argv
// tokens. It is quote-aware (so a flag value containing '&&', '|' or '#' stays
// one token), honors backslash escapes outside quotes, drops a leading "$"
// prompt, and stops at an unquoted '#' comment.
func shellSegments(line string) [][]string {
	var (
		segments [][]string
		argv     []string
		cur      strings.Builder
		quote    rune
		// quoted records that the token came from an explicit "" or '', so an
		// empty argument is still an argument. Dropping it shifts everything
		// after: in `--<flag> "" --<next>`, --<next> becomes the value of
		// --<flag> and an invalid --<next> goes unreported.
		quoted bool
	)

	endToken := func() {
		if cur.Len() > 0 || quoted {
			argv = append(argv, cur.String())
			cur.Reset()
		}
		quoted = false
	}
	endSegment := func() {
		endToken()
		if len(argv) > 0 {
			segments = append(segments, argv)
			argv = nil
		}
	}

	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			if c == '\\' && quote == '"' && i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
				continue
			}
			cur.WriteRune(c)
		case c == '\'' || c == '"':
			quote = c
			quoted = true
		case c == '\\' && i+1 < len(runes):
			i++
			cur.WriteRune(runes[i])
		case c == ' ' || c == '\t':
			endToken()
		case c == '#' && cur.Len() == 0:
			endSegment()
			return segments
		case c == '|' || c == ';' || c == '&' || c == '>' || c == '<' || c == '(' || c == ')':
			endSegment()
		default:
			cur.WriteRune(c)
		}
	}
	endSegment()

	for i := range segments {
		if len(segments[i]) > 1 && segments[i][0] == "$" {
			segments[i] = segments[i][1:]
		}
	}
	return segments
}

// longFlagTokens returns the long-flag tokens in text, in order.
func longFlagTokens(text string) []string {
	matches := longFlagPattern.FindAllStringSubmatch(text, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[2])
	}
	return out
}

// baseName is the last path element of an argv[0], so "./brutus" and
// "/usr/local/bin/brutus" both name the binary.
func baseName(arg string) string {
	if i := strings.LastIndexAny(arg, `/\`); i >= 0 {
		return arg[i+1:]
	}
	return arg
}

// --- suggestions ------------------------------------------------------------

// contains reports whether want is in list.
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// nearest returns the closest candidate to name as a "--<flag>" string, or "" if
// nothing is close enough to be a useful suggestion.
func nearest(name string, candidates []string) string {
	best, bestDistance := "", 0
	for _, c := range candidates {
		d := editDistance(name, c)
		if best == "" || d < bestDistance {
			best, bestDistance = c, d
		}
	}
	limit := len(name) / 2
	if limit < 2 {
		limit = 2
	}
	if best == "" || bestDistance > limit {
		return ""
	}
	return "--" + best
}

// nearestCommand returns the closest subcommand name of path to token.
func nearestCommand(s Surface, path, segment string) string {
	var names []string
	for _, c := range s.Children(path) {
		names = append(names, name(c.Path))
		names = append(names, c.Aliases...)
	}
	best, bestDistance := "", 0
	for _, n := range names {
		d := editDistance(segment, n)
		if best == "" || d < bestDistance {
			best, bestDistance = n, d
		}
	}
	if best == "" || bestDistance > 3 {
		return ""
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
