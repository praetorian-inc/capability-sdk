// Package clisurface derives a structured description of a cobra command tree
// and generates, splices and checks the documentation artifacts built from it.
//
// [Walk] turns a *cobra.Command into a [Surface]. A [Docs], built from a [Config]
// by [New], renders that surface into a JSON artifact and a markdown command
// reference, splices generated regions into a README, and checks committed prose
// against the surface. The intended shape is a hidden "cli-docs" command that
// regenerates the artifacts, plus a CI check that fails when they no longer match.
//
// Construct a Config as a keyed literal; only RegenerateCommand has no default.
//
//	docs, err := clisurface.New(clisurface.Config{
//		RegenerateCommand: "make cli-docs",
//	})
//
// Flag defaults are published verbatim into the JSON artifact, the markdown flag
// table and [Surface.Hash], so never put a secret or a machine-specific path in
// one. A default computed at startup makes the artifacts machine-dependent; declare
// a stable sentinel and resolve it in RunE:
//
//	cmd.Flags().IntVar(&workers, "workers", 0, "worker count (0 = one per CPU)")
//
// The caller is trusted. Config paths are repository-relative and the library
// overwrites what it is given; validation rejects absolute and ".." paths and
// irregular files, but neither is a sandbox — a symlinked parent directory
// relocates a write that passes every check. Writes are in place and not atomic, so
// generate from a clean tree and review with git diff.
//
// A [Surface] is safe to share read-only, including concurrent Hash, Diff,
// LintMarkdown and CheckArtifacts. A [Docs] is read-only once New returns it, so
// its checking methods may be called concurrently; its generating methods write
// files and must not race over the same paths.
package clisurface

// Docs generates and checks one repository's CLI documentation artifacts. It is
// immutable once [New] returns it.
type Docs struct {
	cfg Config
}
