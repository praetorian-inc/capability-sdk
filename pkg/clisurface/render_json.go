package clisurface

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// jsonDoc is the on-disk shape of the machine-readable artifact. Field order here
// is the key order in the rendered file.
type jsonDoc struct {
	SchemaVersion int       `json:"schemaVersion"`
	SurfaceHash   string    `json:"surfaceHash"`
	Commands      []Command `json:"commands"`
}

// renderJSON renders the machine-readable artifact: two-space indentation, no
// HTML escaping, one trailing newline. Key order comes from the struct
// definitions, so the output is byte-stable for a given surface.
func (d *Docs) renderJSON(s Surface) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsonDoc{
		SchemaVersion: schemaVersion,
		SurfaceHash:   s.Hash(),
		Commands:      s.Commands,
	}); err != nil {
		return nil, fmt.Errorf("rendering cli surface json: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseJSON reads a surface back out of the machine-readable artifact.
func (d *Docs) ParseJSON(b []byte) (Surface, error) {
	var doc jsonDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return Surface{}, fmt.Errorf("parsing cli surface json: %w", err)
	}
	if doc.SchemaVersion != schemaVersion {
		return Surface{}, fmt.Errorf("cli surface json has schemaVersion %d, this build renders %d: regenerate with '%s'",
			doc.SchemaVersion, schemaVersion, d.cfg.RegenerateCommand)
	}
	// The hash has to describe the commands it ships with, or a hand-edited artifact
	// passes every later comparison: downstream consumers pin the hash, so one that
	// does not match its own contents is worse than a missing one.
	s := Surface{Commands: doc.Commands}
	if got := s.Hash(); doc.SurfaceHash != got {
		return Surface{}, fmt.Errorf("cli surface json records surfaceHash %s but its commands hash to %s: it looks hand-edited, regenerate with '%s'",
			doc.SurfaceHash, got, d.cfg.RegenerateCommand)
	}
	return s, nil
}
