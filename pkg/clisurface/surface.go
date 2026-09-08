package clisurface

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// schemaVersion is the version of the JSON artifact layout. Bump it when the
// shape of the rendered JSON changes in a way consumers must notice.
const schemaVersion = 1

// The names cobra gives the commands it injects on the first Execute. Excluding
// them keeps the walk deterministic regardless of test ordering. A name is where
// recognition starts, never where it ends: see cobraInjected.
const (
	helpCommandName       = "help"
	completionCommandName = "completion"
)

// cobra's own Use and Short lines for the two injected commands a consumer could
// also declare. Recognition compares verbatim, so a cobra release that changes
// either one documents the command rather than dropping it.
const (
	cobraHelpUse         = helpCommandName + " [command]"
	cobraHelpShort       = "Help about any command"
	cobraCompletionUse   = completionCommandName
	cobraCompletionShort = "Generate the autocompletion script for the specified shell"
)

// HelpFlag is the flag cobra injects on the first Execute. Excluded from the
// surface because whether it is registered depends on execution order; the doc
// linter accepts it everywhere instead (see vocabulary).
const HelpFlag = "help"

// Surface is the complete CLI surface of a command tree. Commands are sorted by
// path and each command's flags are sorted by name, so a Surface renders
// byte-identically across runs.
type Surface struct {
	Commands []Command `json:"commands"`
}

// Command is one node of the command tree.
type Command struct {
	// Path is the full invocation path, e.g. "tool scan targets add".
	Path string `json:"path"`
	// Use is the cobra Use string (the command name plus any argument sketch).
	Use string `json:"use"`
	// Short is the one-line description cobra shows in listings.
	Short string `json:"short"`
	// Aliases are the alternative names that resolve to this command.
	Aliases []string `json:"aliases,omitempty"`
	// Hidden reports whether the command is omitted from help output.
	Hidden bool `json:"hidden,omitempty"`
	// Deprecated is cobra's deprecation notice, empty when not deprecated.
	Deprecated string `json:"deprecated,omitempty"`
	// Runnable reports whether the command does work itself (as opposed to
	// only grouping subcommands).
	Runnable bool `json:"runnable"`
	// Example is cobra's example block, used verbatim in the generated
	// reference. It is part of the surface because it is documentation that
	// must stay honest about the flags it shows.
	Example string `json:"example,omitempty"`
	// Flags are every flag usable on this command: its own, plus the
	// persistent flags inherited from its ancestors.
	Flags []Flag `json:"flags,omitempty"`
}

// Flag is one flag as it appears on one command. The same flag name can appear
// on many commands with different Inherited/Rejected values.
type Flag struct {
	Name       string `json:"name"`
	Shorthand  string `json:"shorthand,omitempty"`
	Type       string `json:"type"`
	Default    string `json:"default,omitempty"`
	Usage      string `json:"usage,omitempty"`
	Deprecated string `json:"deprecated,omitempty"`
	// Inherited reports whether the flag reaches this command as a persistent
	// flag of an ancestor rather than being declared on the command itself.
	Inherited bool `json:"inherited,omitempty"`
	// Hidden reports whether the flag is omitted from help output.
	Hidden bool `json:"hidden,omitempty"`
	// Rejected reports whether the command hard-errors when the flag is set,
	// though it is reachable from the command's flag set -- a family inheriting a
	// root-persistent --timeout but refusing it for its own --scan-timeout. Such a
	// flag is not usable: the reference must not present it and the doc linter
	// must reject examples using it.
	Rejected bool `json:"rejected,omitempty"`
	// RejectedReason is the error the command returns when the flag is set.
	RejectedReason string `json:"rejectedReason,omitempty"`
}

// Walk derives the surface of the tree rooted at root.
//
// Inherited flags are recorded per command, because inheritance alone does not make a
// flag usable: a command's PreRunE may reject one. Walk discovers those by probing
// PreRunE (see probeRejections), so removing a guard changes the surface and reddens
// the gate. Only PreRunE is probed -- PersistentPreRunE and RunE are invisible.
//
// Walk does not mutate the observable tree, which matters because a cobra tree is
// usually a package-level variable shared by every test in a binary. It never calls
// LocalFlags or InheritedFlags (both call mergePersistentFlags, permanently folding
// ancestors' persistent flags into the command's own FlagSet) and never flips a Changed
// bit on a real flag. The one unavoidable write is cmd.Commands() sorting the child
// slice in place -- idempotent, and unobservable since every route to that unexported
// slice calls Commands() first.
//
// Probing runs the consumer's PreRunE once per reachable flag per command, so guards
// must be side-effect-free, cheap, and must not run concurrently with other use of the
// tree. Three obligations Walk cannot enforce: a guard must return (a blocking one
// wedges Walk with nothing to cancel), must not call os.Exit, and must not call
// runtime.Goexit. The deferred recover covers a panic and none of those three.
func Walk(root *cobra.Command) Surface {
	var s Surface
	collect(root, root, &s)
	sort.Slice(s.Commands, func(i, j int) bool { return s.Commands[i].Path < s.Commands[j].Path })
	return s
}

// collect appends cmd and its descendants to s, skipping the commands cobra injects
// as direct children of root. cobra only injects them there, and filtering at every
// depth would drop a legitimate subcommand called "help" and its children.
func collect(cmd, root *cobra.Command, s *Surface) {
	if cmd.Parent() == root && cobraInjected(cmd) {
		return
	}

	s.Commands = append(s.Commands, describe(cmd))

	children := cmd.Commands()
	for i := range children {
		collect(children[i], root, s)
	}
}

// cobraInjected reports whether cobra added cmd rather than the consumer declaring it.
// Provenance decides, not the name: a drift gate calls Walk without executing, so at
// Walk time a root-level "help" or "completion" is usually the consumer's own. Every
// branch defaults to including the command -- documenting an injected command shows up
// in the artifact diff, while silently dropping a declared one is invisible.
func cobraInjected(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
		// cobra's completion wire protocol. Unlike the two below, a consumer
		// never reaches for these names: cobra exports them as constants, they
		// carry no documentation, and cobra adds its own on every Execute
		// whatever the tree holds. The name is the whole test here.
		return true
	case helpCommandName:
		return cmd.Use == cobraHelpUse && cmd.Short == cobraHelpShort && occupiesCobrasHelpSlot(cmd)
	case completionCommandName:
		// InitDefaultCompletionCmd skips injection entirely when the tree already
		// declares a "completion" command, so a match here cannot be shadowing a
		// consumer's own.
		return cmd.Use == cobraCompletionUse && cmd.Short == cobraCompletionShort && !cmd.Runnable()
	}
	return false
}

// occupiesCobrasHelpSlot reports whether the parent's unexported helpCommand field
// points at cmd. cobra exposes no getter, but IsAvailableCommand consults it: for a
// runnable, visible, undeprecated command every other branch returns true, so a false
// answer means this is the help slot. Calling InitDefaultHelpCmd would inject the very
// command being identified. cmd must have a parent.
func occupiesCobrasHelpSlot(cmd *cobra.Command) bool {
	return cmd.Runnable() && !cmd.Hidden && cmd.Deprecated == "" && !cmd.IsAvailableCommand()
}

// describe snapshots a single command.
func describe(cmd *cobra.Command) Command {
	out := Command{
		Path:       cmd.CommandPath(),
		Use:        cmd.Use,
		Short:      cmd.Short,
		Aliases:    append([]string(nil), cmd.Aliases...),
		Hidden:     cmd.Hidden,
		Deprecated: cmd.Deprecated,
		Runnable:   cmd.Runnable(),
		Example:    cmd.Example,
	}

	resolved := resolveFlags(cmd)
	out.Flags = make([]Flag, 0, len(resolved))
	for i := range resolved {
		f := resolved[i].flag
		out.Flags = append(out.Flags, Flag{
			Name:       f.Name,
			Shorthand:  f.Shorthand,
			Type:       f.Value.Type(),
			Default:    f.DefValue,
			Usage:      f.Usage,
			Deprecated: f.Deprecated,
			Inherited:  resolved[i].inherited,
			Hidden:     f.Hidden,
		})
	}

	rejected := probeRejections(cmd, resolved)
	for i := range out.Flags {
		if reason, ok := rejected[out.Flags[i].Name]; ok {
			out.Flags[i].Rejected = true
			out.Flags[i].RejectedReason = reason
		}
	}

	return out
}

// resolvedFlag is one flag reachable from a command, and whether the command
// gets it from an ancestor rather than declaring it itself.
type resolvedFlag struct {
	flag      *pflag.Flag
	inherited bool
}

// resolveFlags returns every flag usable on cmd -- its own, its persistent ones,
// and its ancestors' persistent ones -- sorted by name, reading only cobra's
// non-mutating accessors. Inheritance is classified by flag identity, not name: a
// command shadowing an ancestor's persistent flag holds a different *pflag.Flag and
// is reported as its own, while an inherited flag is the ancestor's pointer whether
// or not cobra has merged the tree.
func resolveFlags(cmd *cobra.Command) []resolvedFlag {
	inherited := map[*pflag.Flag]bool{}
	for parent := cmd.Parent(); parent != nil; parent = parent.Parent() {
		parent.PersistentFlags().VisitAll(func(f *pflag.Flag) { inherited[f] = true })
	}

	var out []resolvedFlag
	seen := map[string]bool{}
	visit := func(f *pflag.Flag) {
		if seen[f.Name] || f.Name == HelpFlag {
			return
		}
		seen[f.Name] = true
		out = append(out, resolvedFlag{flag: f, inherited: inherited[f]})
	}

	cmd.Flags().VisitAll(visit)
	cmd.PersistentFlags().VisitAll(visit)
	for parent := cmd.Parent(); parent != nil; parent = parent.Parent() {
		parent.PersistentFlags().VisitAll(visit)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].flag.Name < out[j].flag.Name })
	return out
}

// probeRejections reports which resolved flags cmd's PreRunE refuses, keyed by flag name
// with the error text as the value.
//
// It runs PreRunE against a shadow command holding copies of the flags, one marked as
// set at a time, so the real tree is never written to. Two guards keep the result
// trustworthy: every copy starts with Changed cleared, and the baseline (no flag set)
// must pass -- a PreRunE that fails unconditionally says nothing about individual flags.
// Probing runs outside cobra's execution lifecycle, so a guard assuming Args were
// validated would panic; that is recovered, not propagated -- an unprobeable command
// yields no rejections, the same conservative answer as one with no PreRunE.
func probeRejections(cmd *cobra.Command, resolved []resolvedFlag) (rejections map[string]string) {
	if cmd.PreRunE == nil {
		return nil
	}

	defer func() {
		if recover() != nil {
			rejections = nil
		}
	}()

	shadow := &cobra.Command{Use: cmd.Name()}
	// A guard that reads the context would otherwise dereference a nil one and panic
	// into the recover above, silently costing this command its rejections.
	shadow.SetContext(context.Background())
	copies := make([]*pflag.Flag, 0, len(resolved))
	for i := range resolved {
		duplicate := *resolved[i].flag
		duplicate.Changed = false
		// The struct copy shares the real flag's Value, so a guard calling Set would
		// write straight through to the live tree. frozenValue makes that a no-op
		// while still reporting the real value to anything that reads it.
		duplicate.Value = frozenValue{duplicate.Value}
		// Drop the shorthand: the probe only needs the flag reachable by name, and a
		// local flag whose shorthand matches an inherited one makes pflag panic on
		// the duplicate -- silently aborting the probe via the recover above.
		duplicate.Shorthand = ""
		copies = append(copies, &duplicate)
		shadow.Flags().AddFlag(&duplicate)
	}

	if err := cmd.PreRunE(shadow, nil); err != nil {
		return nil
	}

	out := map[string]string{}
	for _, f := range copies {
		f.Changed = true
		err := cmd.PreRunE(shadow, nil)
		f.Changed = false
		if err == nil {
			continue
		}
		out[f.Name] = err.Error()
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// frozenValue is a pflag.Value that reports the real value but refuses to change it,
// so probing a command's PreRunE cannot write to the tree being described.
type frozenValue struct {
	pflag.Value
}

// Set discards the write. A guard that normalises a flag rather than only reading it
// would otherwise mutate the live tree during a walk.
func (frozenValue) Set(string) error { return nil }

// Hash is a stable fingerprint of the structural surface: command paths, names,
// aliases, visibility, and each flag's name, shorthand, type, default and usability.
// Prose (Short, Usage, Example) is excluded so rewording help text does not move a hash
// downstream consumers pin. It detects drift, not tampering -- there is no signature --
// and is not an artifact identity: two artifacts differing only in prose share one hash,
// so never use it as a cache key or ETag.
func (s Surface) Hash() string {
	lines := make([]string, 0, len(s.Commands)*4)
	for i := range s.Commands {
		c := &s.Commands[i]
		lines = append(lines, strings.Join([]string{
			"command", c.Path, c.Use, strings.Join(c.Aliases, ","),
			strconv.FormatBool(c.Hidden), strconv.FormatBool(c.Runnable), c.Deprecated,
		}, "\t"))
		for j := range c.Flags {
			f := &c.Flags[j]
			lines = append(lines, strings.Join([]string{
				"flag", c.Path, f.Name, f.Shorthand, f.Type, f.Default,
				strconv.FormatBool(f.Inherited), strconv.FormatBool(f.Hidden),
				strconv.FormatBool(f.Rejected), f.Deprecated,
			}, "\t"))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Command returns the command at the given full path.
func (s Surface) Command(path string) (*Command, bool) {
	for i := range s.Commands {
		if s.Commands[i].Path == path {
			return &s.Commands[i], true
		}
	}
	return nil, false
}

// Children returns the direct subcommands of path, in path order.
func (s Surface) Children(path string) []*Command {
	prefix := path + " "
	var out []*Command
	for i := range s.Commands {
		p := s.Commands[i].Path
		if strings.HasPrefix(p, prefix) && !strings.Contains(p[len(prefix):], " ") {
			out = append(out, &s.Commands[i])
		}
	}
	return out
}

// Root returns the shortest command path in the surface, i.e. the binary name.
func (s Surface) Root() string {
	if len(s.Commands) == 0 {
		return ""
	}
	root := s.Commands[0].Path
	for i := range s.Commands {
		if len(s.Commands[i].Path) < len(root) {
			root = s.Commands[i].Path
		}
	}
	return root
}

// Flag returns the named flag as it applies to the command at path.
func (c *Command) Flag(name string) (*Flag, bool) {
	for i := range c.Flags {
		if c.Flags[i].Name == name {
			return &c.Flags[i], true
		}
	}
	return nil, false
}

// FlagByShorthand returns the flag carrying the single-character shorthand.
func (c *Command) FlagByShorthand(short string) (*Flag, bool) {
	for i := range c.Flags {
		if c.Flags[i].Shorthand != "" && c.Flags[i].Shorthand == short {
			return &c.Flags[i], true
		}
	}
	return nil, false
}

// FlagNames returns every long flag name that appears anywhere in the surface.
func (s Surface) FlagNames() []string {
	seen := map[string]bool{}
	var out []string
	for i := range s.Commands {
		c := &s.Commands[i]
		for j := range c.Flags {
			if name := c.Flags[j].Name; !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
