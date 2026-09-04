// Package clisurface derives a structured description of a cobra command tree
// and generates, splices and checks the documentation artifacts built from it.
//
// Walk turns a *cobra.Command into a [Surface]: every command the consumer
// declares -- hidden ones included -- with its aliases and its resolved flags.
// A [Docs], built from a [Config] by [New], renders that surface into a JSON
// artifact and a markdown command reference, splices generated regions into a
// README, and checks committed prose and Go comments against the surface so
// documentation cannot silently drift from the binary. The intended shape is a
// hidden "cli-docs" command in the consumer's own binary that regenerates the
// artifacts, plus a CI check that fails when the committed files no longer
// match.
//
// Construct a Config as a keyed literal: fields are added over time, and only
// RegenerateCommand has no default.
//
//	docs, err := clisurface.New(clisurface.Config{
//		RegenerateCommand: "make cli-docs",
//	})
//
// # What is documented, and what is not
//
// The split is per artifact, not per command class. [Walk] drops only the help
// and shell-completion commands cobra injects into a tree itself; every command
// the consumer declares reaches the [Surface] whatever its hidden or deprecated
// state, and each artifact then applies its own population rule. Read those
// rules per artifact rather than per class: a command can be hidden,
// deprecated, both or neither, and the artifacts do not agree on what to do
// with the both case.
//
// The JSON artifact and the generated markdown reference carry every command in
// the surface; neither filters on either state anywhere. The JSON artifact
// publishes both states as fields, "hidden": true and "deprecated". The
// reference annotates them in two places, which differ for a command that is
// both: its own section emits one line per state -- "- Hidden: not shown in
// `--help` output" and "- Deprecated: ..." -- so a command that is both carries
// both lines, while the command index annotates one only, deprecation first, so
// the same command reads "(deprecated: ...)" there and is not marked hidden.
//
// The two generated README regions -- the Quick Start subcommand listing and
// the alias table -- carry only top-level commands that are not hidden, and
// annotate neither state: the subcommand listing writes Command.Short verbatim,
// and the alias table carries only a name and its aliases, listing just the
// commands that declare any. Hiding alone decides these regions, so a hidden
// command is absent from both whether or not it is also deprecated.
//
// That split is deliberate. Hiding a command is a statement that users should
// not discover it, so it stays out of the README, which is the surface users
// read to find out what the tool does -- and deprecating it does not put it
// back, because a command withheld from the discovery surface is not
// reintroduced to it by being on its way out. Deprecating a command is a
// statement that users must be told to stop using it, so the reference and the
// JSON artifact publish its notice: they are the complete record rather than a
// discovery surface, which is why hidden commands belong in them too. The
// README regions stay a bare listing of name, description and aliases.
//
// Two tests lock the two halves, each over the surface it actually covers --
// TestRenderRegionsSkipsHiddenSubcommands over the rendered README subcommand
// region, and TestRenderMarkdownAnnotatesHiddenAndDeprecatedCommands over the
// markdown reference, whose cases between them reach every annotation a command
// or a flag can carry -- so a change to either half fails loudly rather than
// quietly editing what the artifacts disclose.
//
// # Flag defaults are published verbatim
//
// A flag's default value is captured exactly as cobra reports it and written
// into three published surfaces: the "default" field of each flag in the JSON
// artifact, the default column of the markdown flag table, and the input to
// [Surface.Hash]. So never put a secret, a credential, or a machine-specific
// path in a flag default -- it becomes committed, diffable content in the
// consumer's repository.
//
// This also means a default computed at startup makes the artifacts
// machine-dependent, and regenerating them on another host produces a spurious
// diff. A default derived from the environment -- a worker count from the CPU
// count, a cache directory from the home directory -- must therefore be
// declared as a stable sentinel and resolved inside RunE, not in the flag
// registration:
//
//	cmd.Flags().IntVar(&workers, "workers", 0, "worker count (0 = one per CPU)")
//
// The artifacts then record "0" on every host, and the documented meaning of
// the sentinel tells a reader what it resolves to.
//
// # The caller is trusted
//
// Every path in a Config is repository-relative, and the library writes to and
// overwrites the paths it is given. Validation rejects an absolute path and one
// containing a ".." element, which catches a mistake -- it is not a sandbox and
// is not a defence against a hostile configuration. Nor could it be: it rules on
// the shape of a string, while the filesystem decides where that string leads.
// A symlink anywhere along an entirely valid path puts the write or the read
// outside the repository, and no amount of checking the string can see that.
// Write refuses a target that already exists as something other than a regular
// file, and the lint walks read regular files only, precisely because those two
// operations are where the consequence lands -- but they are narrow guards on
// two operations, not containment. This is a code generator invoked by the
// repository it generates into: whoever supplies the Config already controls
// the source tree.
//
// The command tree is trusted on the same terms. Walk recurses over it with no
// visited set, so a tree containing a cycle -- a is a child of b and b a child
// of a, which cobra allows because it rejects only self-addition -- recurses
// until the stack limit and takes the process down with a fatal stack overflow.
// That is not a panic, and no deferred recover can reach it. A cobra tree is
// the consumer's own code and a cycle in one is a construction bug in that
// code, so Walk does not carry a visited set on every node to detect it.
//
// Writes are in place and not atomic. A failure partway through can leave an
// artifact half-written, so run generation from a clean working tree and review
// the result with git diff before committing -- the same discipline any
// generated, committed file needs.
//
// # Concurrency
//
// Walk is single-goroutine-per-tree, and the [Surface] it returns -- with the
// [Command] and [Flag] values inside it -- is safe to share read-only,
// including concurrent Hash, Diff, LintMarkdown and CheckArtifacts on the same
// value, provided no one mutates the Surface after handing it over. A Docs is
// read-only once New returns it, so its checking methods may be called
// concurrently; its generating methods write files and must not race each other
// over the same paths. An [Allowlist] is shareable on the same terms, and
// [Allowlist.Entries] builds a fresh slice on every call, so no two readers of
// one allowlist can reach the same backing array.
//
// # Notes for maintainers
//
// Importing this package puts cobra and pflag into the consumer's module graph,
// at whatever versions this module requires -- versions the committed artifacts
// do not pin, so a cobra upgrade can legitimately change generated output.
//
// Two house conventions are set aside deliberately. Errors that report a
// rejected configuration carry no %w verb -- errors.New where the message has
// nothing to interpolate, fmt.Errorf where it quotes the offending value --
// because there is no underlying cause to unwrap; %w is used where a real cause
// exists.
// And the tests are in package clisurface rather than clisurface_test, because
// the ported suite exercises unexported helpers directly and stamps unexported
// fields on the values it asserts against.
//
// Generated prose names the tool by title-casing the first rune of the root
// command's name and nothing else, so a brand with internal capitalisation
// renders exactly as the binary is spelled.
package clisurface

// Docs generates and checks one repository's CLI documentation artifacts. It is
// immutable once [New] returns it: the configuration it resolved is readable
// through [Docs.Config] and cannot be changed afterwards.
type Docs struct {
	cfg Config
}
