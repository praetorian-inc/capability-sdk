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

// usePlaceholders are the Use-string fields that describe the shape of an
// invocation rather than sketching a positional argument, so hasArgSketch must
// not read any of them as one.
//
// "[flags]" is cobra's own, appended verbatim to the usage line of any command
// that has flags. The other four mean "a subcommand goes here": cobra writes
// "[command]" itself -- in its usage template, and as the Use of the help
// command it generates -- and the angle-bracket and "subcommand" spellings are
// the same convention written by hand, which this codebase's Use strings mix
// freely for real arguments too ("[owner/repo]" beside "<domain>").
//
// Reading "[command]" as an argument was a measured false negative, and the
// worst-placed one available: a command whose Use says a subcommand goes here
// is exactly where a misspelled subcommand in prose is most certainly a typo,
// and takesPositional went silent there. With "config [command]" runnable over
// a child "show", "tool config shwo" drew no finding at all.
//
// Membership is case-folded. Cobra emits only the lowercase spellings, but the
// four hand-written ones carry no such guarantee, and "[COMMAND]" names a
// subcommand slot just as plainly as "[command]" does. Folding errs toward
// reporting -- a skipped field makes hasArgSketch answer false, which keeps the
// linter talking -- which is the recoverable direction hasArgSketch already
// documents: the porter clears a report by naming the argument in Use, and
// gains a truer "--help" doing it, whereas silence hides a real typo with
// nothing to signal that it did.
var usePlaceholders = map[string]bool{
	"[flags]":      true,
	"[command]":    true,
	"<command>":    true,
	"[subcommand]": true,
	"<subcommand>": true,
}

// longFlagPattern matches a long flag token in prose or in a Go comment.
// Group 2 is the token. The leading group requires the dashes to start a word,
// so neither "// -----" rule comments, nor "--" used as a dash-dash separator,
// nor "dash--dash" inside a word can look like a flag.
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
	// example of a removed flag is given here: this package's own comments are
	// linted, and allowlisting a real removed flag to quote it would suppress
	// that name everywhere, including in the README the gate exists to police.
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
	// The two get different advice: the allowlist only holds flag tokens (see
	// [Docs.ParseAllowlist]), so offering it for a misspelled subcommand would
	// send the reader to write an entry the allowlist parser rejects.
	Subcommand bool

	// The four fields below are the resolved [Config] values [Issue.String]
	// needs in order to name a path or a command. A producing method stamps
	// them in (see stamp), which is what lets String keep its exact wording
	// without taking a receiver or four more arguments. The cost is that an
	// Issue a caller builds itself renders without them: String stays safe on
	// the zero value -- naming no artifact and offering no allowlist path --
	// rather than panicking.
	jsonPath          string
	markdownPath      string
	allowlistPath     string
	regenerateCommand string
}

// stamp records the resolved [Config] values [Issue.String] needs on one issue.
// Every method that produces issues passes each of them through here, so what a
// rendered issue names is what its own Docs was configured with, and never a
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

// whollyGenerated reports whether every line of the issue's file is generated,
// and so must never be hand-edited. The configured README is deliberately
// excluded: only two regions of it are generated, so a lint hit there is
// normally in hand-written prose.
//
// The empty-File guard is what keeps an unstamped issue out of the generated
// branch: on the zero value every one of these fields is "", so without it File
// would match jsonPath and String would advertise regenerating an artifact it
// cannot even name.
func (i Issue) whollyGenerated() bool {
	return i.File != "" && (i.File == i.jsonPath || i.File == i.markdownPath)
}

// Allowlist holds deliberately documented tokens and why each is allowed.
type Allowlist struct {
	reasons map[string]string
}

// ParseAllowlist reads an allowlist file. Every entry is one token
// ("--<flag>" or "-<x>") followed by a '#' comment giving the reason; blank lines
// and whole-line comments are ignored. The reason is mandatory: an entry
// without one is an error, because an unexplained exception is how a stale
// reference survives forever.
//
// A parse error names the configured [Config.AllowlistPath], so a consumer that
// moved the file is told where the bad entry actually is.
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
// Fenced code blocks are parsed as shell: line continuations are joined,
// pipelines are split, and only segments whose argv[0] is the CLI binary are
// checked — every flag of every other tool in an example pipeline is ignored,
// which is what keeps the false-positive rate at zero. Prose outside fences is
// checked more loosely: only backticked long-flag tokens, and only against the
// union of every flag in the tree, because prose rarely says which command it
// means.
//
// The argv[0] rule is what buys the zero false-positive rate, and it costs
// reach: an invocation the binary does not lead — "sudo brutus …", "time brutus
// …", "FOO=bar brutus …" — is skipped rather than checked. Recognizing prefixes
// one at a time would trade a guarantee for a list that is never finished, so
// examples are written with the binary first. There are none of the other shape
// in this repository.
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

// fenceDelimiter returns the fence a line opens a code block with, or "" when the line
// does not open one.
//
// It returns the whole run of backticks or tildes, not just three of them. The length
// is load-bearing: a block opened with four backticks may contain a three-backtick line
// as content, and closing on it early would read the rest of the document as prose and
// the following prose as shell.
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

// lintInvocation checks one "brutus ..." invocation.
//
// It works in the two stages cobra works in. First it resolves the command,
// stepping over flags and the values they consume; then it validates every flag
// in the invocation against the command that was finally resolved. That order is
// not incidental — cobra dispatches to the resolved command and parses the whole
// argv against *that* command's flag set, so where a flag sits relative to the
// subcommand does not change whether it is accepted.
//
// Validating each flag against whichever command happened to be resolved when it
// was read gets this wrong in both directions:
//
//   - Reporting a flag against the root because it was written before the
//     subcommand. `brutus --json enum apollo --domain example.com` is legal, but
//     --domain would be reported as not existing on "brutus".
//   - Missing a flag the resolved command refuses. `brutus --timeout 5s logon`
//     fails at runtime because the logon family rejects the inherited --timeout,
//     and `brutus --version logon` fails because --version is local to the root
//     — neither is excused by being written early.
//
// Values are stepped over using the command resolved so far, which is what cobra
// does too: a non-boolean flag takes the next argument, a value-taking shorthand
// takes the rest of its token ("-oresults.json") or the next argument, and "--"
// ends flag parsing. Reading a value as a flag would report its characters as
// nonexistent shorthands.
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
	// that is not a subcommand: from there on argv holds this command's
	// arguments, and an argument that happens to spell a subcommand name is not
	// one.
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
			// Not a subcommand, so from here on argv holds this command's
			// arguments. That is true whether or not the token is worth
			// reporting, so resolving stops on every path out of here: were it
			// left on, a later argument spelling a real subcommand name would
			// advance cmd and every flag in the line would then be judged
			// against the wrong command.
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

// longFlagTakesNext reports whether the argument after a "--<name>" token is
// that flag's value rather than a token of its own.
//
// A "--<name>=<value>" token carries its own value. Otherwise any non-boolean
// flag takes the next argument. A flag cmd does not declare is guessed from
// shape — anything that does not itself look like a flag — so that one unknown
// flag does not also get its value read as a bogus subcommand.
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

// shortFlagTakesNext reports whether the argument after a "-x" token, or a
// "-xyz" cluster, is a value of that cluster. pflag clusters booleans freely,
// and the first flag that takes a value swallows the rest of the token
// ("-oresults.json", "-o=results.json") or, when the token ends there, the next
// argument ("-o results.json").
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

// checkShortFlags validates a "-x" token, or a "-xyz" cluster, against cmd. It
// reads the cluster the way pflag does (see shortFlagTakesNext): scanning a
// flag's value as more shorthands is how "-oresults.json" turns into six
// invented flags.
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
// children is worth reporting as a misspelled subcommand.
//
// Two conditions must hold. cmd must have children, or there is no subcommand
// to have misspelled and nothing to suggest. And cmd must not legitimately
// take a positional itself: when a command both dispatches to children and
// accepts an argument of its own, a non-child positional is as likely to be
// that argument as a typo, and reporting it forces correct documentation to be
// rewritten into something false.
//
// Two limitations follow, stated rather than hidden. A genuinely misspelled
// subcommand of a parent that both runs and sketches an argument is no longer
// reported: with "github [owner/repo]" runnable, "tool github tagets" is
// accepted. And a command that really takes a positional but does not sketch
// it in Use is still reported, because its own declared interface says it
// takes none. Everything else stays covered, the root included -- see
// takesPositional for why that mattered enough to shape the predicate.
func reportsBogusSubcommand(s Surface, cmd *Command) bool {
	return len(s.Children(cmd.Path)) > 0 && !takesPositional(cmd)
}

// takesPositional reports whether cmd's own declared interface says it accepts
// a positional argument.
//
// The surface does not carry cobra's Args validator, which is the authoritative
// answer, and adding it would change the JSON schema and invalidate every
// consumer's committed docs/cli-surface.json golden. So this reads the two
// signals the surface already has, and needs both.
//
// Runnable alone is not enough, and that is measured rather than assumed: a
// root command with a RunE and subcommands is the overwhelmingly common cobra
// shape, so treating "runnable" as "takes an argument" would suppress mistyped
// subcommand reports at the top level of nearly every CLI -- precisely where a
// typo in documentation is most likely and where nearestCommand pays off most.
//
// The second signal is the Use string, which is cobra's own user-facing
// argument sketch: "github [owner/repo]" documents a positional, "version"
// documents none. The recognized shapes are enumerated in hasArgSketch below.
func takesPositional(cmd *Command) bool {
	return cmd.Runnable && hasArgSketch(cmd.Use)
}

// hasArgSketch reports whether a cobra Use string sketches a positional
// argument after the command name.
//
// The recognized shapes, exhaustively: the first field is the command's own
// name and is dropped; a field beginning with "-" is a flag, not a positional;
// a field in usePlaceholders describes the invocation's shape rather than an
// argument ("[flags]", and the four spellings of "a subcommand goes here") and
// is not a positional; every other non-empty field is an argument sketch,
// whatever its punctuation, so "[owner/repo]", "<domain>", "TARGET" and a bare
// "path" all count.
//
// Nothing here can panic or mis-slice: strings.Fields tolerates any spacing and
// returns an empty slice for an empty or all-space Use, which yields false.
// False is also the deliberate default for a Use string this does not
// understand, because false means the linter keeps reporting. That is the safe
// direction for an unrecognized shape: an under-documented Use is itself a
// documentation defect -- cobra prints Use verbatim in help output, so a
// command whose sketch omits an argument it really takes is already lying to
// its users -- and both ways of clearing the resulting report (correct the
// prose, or document the argument in Use) leave the CLI's documentation more
// honest than it was. Silence, by contrast, cannot be recovered from: it hides
// a real typo with nothing to signal that it did.
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

// lintGoComments checks every long-flag token in the comments of one Go file.
// This is the check that keeps a renamed flag from surviving in a comment that
// no compiler and no test would ever read.
//
// It is unexported because linting a repository is the supported entry point: a
// consumer names the directories to walk in [Config] rather than reading and
// passing files itself.
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

// LintScope records what a lint run actually reached: the markdown documents it
// read, the directories it walked for Go files, the Go files it found under
// them, the entries it declined to read, and the allowlist that was in force.
//
// It exists so [LintReport] can state its own coverage. A scope that matched
// nothing is the failure mode this type is for: a walk root that is missing, or
// is a symlink, lints zero files, and a report saying only that there were no
// issues is indistinguishable from a clean repository. Reporting the counts
// turns that silence into a visible zero.
type LintScope struct {
	// MarkdownFiles are the repo-relative markdown documents that were linted.
	MarkdownFiles []string
	// GoDirs are the repo-relative directories that were walked for Go files.
	GoDirs []string
	// GoFiles are the repo-relative Go files found under GoDirs and linted.
	GoFiles []string
	// SkippedIrregular are the repo-relative entries the run declined to read
	// because they are not regular files -- a symlink, a device, a FIFO, a
	// socket -- along with any configured Go directory that exists but is not a
	// directory. Reading such an entry whole is either unbounded or
	// never-returning, and following one leaves the repository altogether, so
	// what is read is selected by the entry's type rather than by its name.
	//
	// An entry lands here whether a walk matched it by name or
	// [Config.LintedMarkdown] named it outright: the two feed the same read and
	// carry the same hazard, and a configured path is trusted as a value, not as
	// whatever it resolves to on disk. They are listed rather than dropped for
	// the reason the rest of this type exists: an unexplained gap in coverage
	// reads as a clean repository.
	SkippedIrregular []string
	// Allowlist is the allowlist the run suppressed tokens with.
	Allowlist Allowlist
}

// LintReport renders lint issues as a failure message that ends with the scope
// the run actually covered.
//
// The scope line is appended rather than woven in, so a caller matching on the
// issue lines is unaffected by it. It reports the allowlist size beside the file
// counts because a suppressed token is invisible in the issue list by
// construction: a reader who cannot see that forty tokens are allowlisted
// cannot tell a clean repository from a silenced one.
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
		// quoted records that the current token came from an explicit "" or '', so an
		// empty argument is still an argument. Dropping it shifts everything after it:
		// given `--<flag> "" --<next>`, the empty value disappears, --<next> is read as
		// the value of --<flag>, and an invalid --<next> goes unreported.
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
