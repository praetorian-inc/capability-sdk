package capability

import (
	"strconv"
	"time"
)

// ExecutionContext carries runtime context into Match and Invoke.
type ExecutionContext struct {
	// Manual is true when a human explicitly triggered the capability
	// (e.g. via the UI) rather than an automated pipeline.
	Manual bool

	// Relevant for PeriodicCapabilities to know if
	// its been >= Full() time since the last successful scan
	Full bool

	// Parameters holds the capability's declared parameters with their
	// runtime values resolved.
	Parameters Parameters

	Metrics Metrics

	// Cache, when non-nil, gives the capability access to the runtime's result cache.
	// Capabilities that compute expensive results across many similar inputs (e.g. nuclei
	// scans against equivalent webpages) can wrap their inner work in Cache.Call to
	// dedupe. The runtime is responsible for partitioning by capability and tenant; the
	// capability supplies a similarity hash and a deterministic key set for exact-match
	// fallback. Implementations are expected to be safe for concurrent use.
	Cache Cache
}

// Cache is the runtime-supplied cache facility attached to ExecutionContext. The runtime
// determines storage backend, namespace, and similarity threshold; capabilities only decide
// what to cache, how to fingerprint the content, and how to scope it.
type Cache interface {
	// Call runs fn on cache miss and stores the result for future calls.
	//
	//  - ttl: unix timestamp at which the entry expires (0 = never expire).
	//  - similarityHash: 64-bit locality-sensitive hash of the *input content*. Pass 0 to
	//    opt out of similarity matching and use only the exact-key path. The hash should
	//    reflect content only; isolate distinct scan configurations via partitionKeys
	//    instead of folding them into the hash.
	//  - fn: produces the value to cache, returning the marshaled bytes and an error.
	//    Called only on cache miss; the runtime serializes its result into storage as-is.
	//  - partitionKeys: deterministic components that scope the cache *partition*. Two
	//    calls with different partitionKeys never share entries, even when their
	//    similarityHash matches. Use this for scan-config disambiguation (template set,
	//    rate limit, mode flags) — anything where a hit across the boundary would be
	//    semantically wrong. Pass nil if there's no need to subdivide.
	//  - contentKeys: deterministic components that form the *exact-match* key within a
	//    partition. The runtime composes them into a stable cache row key for writeback
	//    identity and for the exact-key fallback when similarity-based lookup misses.
	//
	// Returns the cached or freshly computed bytes. Errors from fn are returned without
	// any storage side-effects.
	Call(ttl int64, similarityHash uint64, fn func() ([]byte, error), partitionKeys []string, contentKeys ...string) ([]byte, error)
}

type Metrics struct {
	increment func(key string, delta int)
}

func NewMetrics(fn func(key string, delta int)) Metrics {
	return Metrics{increment: fn}
}

func (m Metrics) IncrementMetric(key string, delta int) {
	if m.increment != nil {
		m.increment(key, delta)
	}
}

// Parameter declares a single configurable parameter for a capability.
// When returned from Capability.Parameters(), only the declarative fields
// are set. At runtime, the wrapper populates Value from the job config
// before passing parameters through ExecutionContext.Parameters.
type Parameter struct {
	// Name is the parameter key.
	Name string

	// Description is a human/LLM-friendly explanation of the parameter.
	Description string

	// Type is the value type: "string", "int", "float", or "bool".
	Type string

	// Required marks the parameter as mandatory.
	Required bool

	// Default is the string representation of the default value.
	Default string

	// Options lists suggested choices for enum-style parameters.
	Options []string

	// Value is the resolved runtime value. Empty in declarations;
	// populated by the wrapper before Match/Invoke.
	Value string
}

// Parameters is a list of resolved parameter values.
type Parameters []Parameter

// resolve returns the effective string value for a parameter (Value if
// set, else Default) and whether the parameter was found.
func (p Parameters) resolve(name string) (string, bool) {
	for _, param := range p {
		if param.Name == name {
			if param.Value != "" {
				return param.Value, true
			}
			if param.Default != "" {
				return param.Default, true
			}
			return "", false
		}
	}
	return "", false
}

// GetString returns the value for the named parameter as a string.
func (p Parameters) GetString(name string) (string, bool) {
	return p.resolve(name)
}

// GetInt returns the value for the named parameter parsed as an int.
func (p Parameters) GetInt(name string) (int, bool) {
	s, ok := p.resolve(name)
	if !ok {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}

// GetBool returns the value for the named parameter parsed as a bool.
func (p Parameters) GetBool(name string) (bool, bool) {
	s, ok := p.resolve(name)
	if !ok {
		return false, false
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return false, false
	}
	return v, true
}

// GetFloat returns the value for the named parameter parsed as a float64.
func (p Parameters) GetFloat(name string) (float64, bool) {
	s, ok := p.resolve(name)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// String creates a string parameter with the given name and description.
func String(name, description string) Parameter {
	return Parameter{Name: name, Description: description, Type: "string"}
}

// Int creates an integer parameter with the given name and description.
func Int(name, description string) Parameter {
	return Parameter{Name: name, Description: description, Type: "int"}
}

// Bool creates a boolean parameter with the given name and description.
func Bool(name, description string) Parameter {
	return Parameter{Name: name, Description: description, Type: "bool"}
}

// Float creates a float parameter with the given name and description.
func Float(name, description string) Parameter {
	return Parameter{Name: name, Description: description, Type: "float"}
}

// WithDefault sets the default value for the parameter.
func (p Parameter) WithDefault(val string) Parameter {
	p.Default = val
	return p
}

// WithOptions sets the suggested choices for an enum-style parameter.
func (p Parameter) WithOptions(opts ...string) Parameter {
	p.Options = opts
	return p
}

// WithRequired marks the parameter as mandatory.
func (p Parameter) WithRequired() Parameter {
	p.Required = true
	return p
}

// Capability is the minimal interface for building a capability.
type Capability[T any] interface {
	Name() string
	Description() string
	Input() any
	Parameters() []Parameter
	Match(ctx ExecutionContext, input T) error
	Invoke(ctx ExecutionContext, input T, output Emitter) error
}

// PeriodicCapability is an optional interface that capabilities can implement to
// control how often they run full scans. A full scan will have Full set in the ExecutionContext
type PeriodicCapability interface {
	Full() time.Duration
}

// TimeoutCapability is an optional interface that capabilities can implement
// to declare their expected worst-case execution time. The returned value is
// used as the SQS visibility timeout (in minutes). When not implemented, the
// default 10-minute timeout applies.
type TimeoutCapability interface {
	Timeout() int
}

// Emitter is the output interface. Capabilities call Emit() with
// capmodel types. In chariot this wraps job.Send(); in tests it
// collects into a slice.
type Emitter interface {
	Emit(models ...any) error
}

// EmitterFunc adapts a function to the Emitter interface.
type EmitterFunc func(models ...any) error

func (f EmitterFunc) Emit(models ...any) error { return f(models...) }
