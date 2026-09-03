// Package clisurface derives a structured description of a cobra command tree
// and generates, splices and checks the documentation artifacts built from it.
//
// Walk turns a *cobra.Command into a [Surface]: every command -- hidden ones
// included -- with its aliases and its resolved flags. A [Docs], built from a
// [Config] by [New], renders that surface into a JSON artifact and a markdown
// command reference, splices generated regions into a README, and checks
// committed prose and Go comments against the surface so documentation cannot
// silently drift from the binary. The intended shape is a hidden "cli-docs"
// command in the consumer's own binary that regenerates the artifacts, plus a
// CI check that fails when the committed files no longer match.
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
// The split is per artifact, not global, and [Walk] itself filters nothing:
// every command reaches the [Surface], and each renderer decides what to
// disclose. A hidden command is omitted from the generated README regions --
// the Quick Start subcommand listing and the alias table -- and is present in
// the generated markdown reference, flagged "(hidden)" in the index and
// annotated "Hidden: not shown in `--help` output" in its own section; the JSON
// artifact carries it too, with "hidden": true. A deprecated command is present
// in every artifact, and annotated in the generated markdown reference --
// "(deprecated: ...)" in the index and a "- Deprecated:" line in its own
// section -- and in the JSON artifact, through a "deprecated" field; the two
// README regions list it with no notice at all, because the subcommand listing
// writes Command.Short verbatim and the alias table carries only a name and
// its aliases.
//
// That split is deliberate: hiding a command is a statement that users should
// not discover it, so it stays out of the README, which is the surface users
// read to find out what the tool does. Deprecating one is a statement that
// users must be told to stop using it, so it is never dropped from any
// artifact, and the generated reference and the JSON artifact publish its
// notice: they are the complete record rather than a discovery surface, which
// is why hidden commands belong in them too. The README regions stay a bare
// listing of name, description and aliases.
//
// Two tests lock the two halves, each over the surface it actually covers --
// TestRenderRegionsSkipsHiddenSubcommands over the rendered README subcommand
// region, and TestRenderMarkdownAnnotatesHiddenAndDeprecatedCommands over the
// markdown reference -- so a change to either half fails loudly rather than
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
// is not a defence against a hostile configuration. This is a code generator
// invoked by the repository it generates into: whoever supplies the Config
// already controls the source tree.
//
// Writes are in place and not atomic. A failure partway through can leave an
// artifact half-written, so run generation from a clean working tree and review
// the result with git diff before committing -- the same discipline any
// generated, committed file needs.
//
// # Concurrency
//
// Walk is single-goroutine-per-tree, and the values it returns ([Surface],
// [Command], [Flag], Allowlist) are safe to share read-only -- including
// concurrent Hash, Diff, LintMarkdown and CheckArtifacts on the same value,
// provided no one mutates the Surface after handing it over. A Docs is
// read-only once New returns it, so its checking methods may be called
// concurrently; its generating methods write files and must not race each other
// over the same paths.
//
// # Notes for maintainers
//
// Importing this package puts cobra and pflag into the consumer's module graph,
// at whatever versions this module requires -- versions the committed artifacts
// do not pin, so a cobra upgrade can legitimately change generated output.
//
// Two house conventions are set aside deliberately. Errors that report a
// rejected configuration are built with fmt.Errorf and no %w verb, because
// there is no underlying cause to unwrap; %w is used where a real cause exists.
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
