package capability_test

import (
	"errors"
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- mock capability --------------------------------------------------------

type domainScanner struct{}

func (d *domainScanner) Name() string        { return "domain-scanner" }
func (d *domainScanner) Description() string { return "discovers subdomains" }
func (d *domainScanner) Input() any          { return capmodel.Domain{} }
func (d *domainScanner) Parameters() []capability.Parameter {
	return []capability.Parameter{
		capability.Int("threads", "Number of concurrent threads").WithDefault("4"),
		capability.Int("timeout", "Timeout in seconds").WithRequired(),
		capability.Bool("verbose", "Enable verbose output").WithDefault("false"),
		capability.String("mode", "Scan mode").WithDefault("passive").WithOptions("passive", "active", "stealth"),
	}
}
func (d *domainScanner) Match(_ capability.ExecutionContext, input capmodel.Domain) error {
	if input.Domain == "" {
		return errors.New("empty domain")
	}
	return nil
}
func (d *domainScanner) Invoke(ctx capability.ExecutionContext, input capmodel.Domain, out capability.Emitter) error {
	mode, _ := ctx.Parameters.GetString("mode")
	return out.Emit(capmodel.Asset{DNS: mode + "." + input.Domain, Name: mode + "." + input.Domain})
}

// compile-time check
var _ capability.Capability[capmodel.Domain] = (*domainScanner)(nil)

// --- tests ------------------------------------------------------------------

func TestCapability_Invoke(t *testing.T) {
	cap := &domainScanner{}

	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	// Parameters.GetString falls back to Default when Value is empty
	ctx := capability.ExecutionContext{
		Parameters: cap.Parameters(),
	}

	err := cap.Invoke(ctx, capmodel.Domain{Domain: "example.com"}, out)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset, ok := emitted[0].(capmodel.Asset)
	require.True(t, ok)
	assert.Equal(t, "passive.example.com", asset.DNS)
}

func TestCapability_Match(t *testing.T) {
	cap := &domainScanner{}

	assert.NoError(t, cap.Match(capability.ExecutionContext{}, capmodel.Domain{Domain: "example.com"}))
	assert.Error(t, cap.Match(capability.ExecutionContext{}, capmodel.Domain{}))
}

func TestCapability_Metadata(t *testing.T) {
	cap := &domainScanner{}

	assert.Equal(t, "domain-scanner", cap.Name())
	assert.Equal(t, "discovers subdomains", cap.Description())

	_, ok := cap.Input().(capmodel.Domain)
	assert.True(t, ok)
}

func TestCapability_Parameters(t *testing.T) {
	cap := &domainScanner{}
	params := cap.Parameters()

	require.Len(t, params, 4)

	assert.Equal(t, "threads", params[0].Name)
	assert.Equal(t, "int", params[0].Type)
	assert.Equal(t, "4", params[0].Default)
	assert.False(t, params[0].Required)

	assert.Equal(t, "timeout", params[1].Name)
	assert.Equal(t, "int", params[1].Type)
	assert.True(t, params[1].Required)

	assert.Equal(t, "verbose", params[2].Name)
	assert.Equal(t, "bool", params[2].Type)
	assert.Equal(t, "false", params[2].Default)

	assert.Equal(t, "mode", params[3].Name)
	assert.Equal(t, "string", params[3].Type)
	assert.Equal(t, "passive", params[3].Default)
	assert.Equal(t, []string{"passive", "active", "stealth"}, params[3].Options)
}

func TestCapability_ParameterPassthrough(t *testing.T) {
	cap := &domainScanner{}

	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "mode", Default: "passive", Value: "active"},
			{Name: "threads", Default: "4", Value: "8"},
		},
	}

	err := cap.Invoke(ctx, capmodel.Domain{Domain: "example.com"}, out)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset, ok := emitted[0].(capmodel.Asset)
	require.True(t, ok)
	assert.Equal(t, "active.example.com", asset.DNS)
}

func TestCapability_ParameterFallsBackToDefault(t *testing.T) {
	cap := &domainScanner{}

	var emitted []any
	out := capability.EmitterFunc(func(models ...any) error {
		emitted = append(emitted, models...)
		return nil
	})

	// Value is empty, so GetString("mode") should return Default
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "mode", Default: "passive"},
		},
	}

	err := cap.Invoke(ctx, capmodel.Domain{Domain: "example.com"}, out)
	require.NoError(t, err)
	require.Len(t, emitted, 1)

	asset, ok := emitted[0].(capmodel.Asset)
	require.True(t, ok)
	assert.Equal(t, "passive.example.com", asset.DNS)
}

func TestParameters_GetString(t *testing.T) {
	params := capability.Parameters{
		{Name: "mode", Default: "passive", Value: "active"},
		{Name: "empty"},
	}

	v, ok := params.GetString("mode")
	assert.True(t, ok)
	assert.Equal(t, "active", v)

	_, ok = params.GetString("empty")
	assert.False(t, ok)

	_, ok = params.GetString("nonexistent")
	assert.False(t, ok)
}

func TestParameters_GetString_Default(t *testing.T) {
	params := capability.Parameters{
		{Name: "mode", Default: "passive"},
	}

	v, ok := params.GetString("mode")
	assert.True(t, ok)
	assert.Equal(t, "passive", v)
}

func TestParameters_GetInt(t *testing.T) {
	params := capability.Parameters{
		{Name: "threads", Default: "4", Value: "8"},
		{Name: "defaulted", Default: "10"},
		{Name: "bad", Value: "not-a-number"},
		{Name: "empty"},
	}

	v, ok := params.GetInt("threads")
	assert.True(t, ok)
	assert.Equal(t, 8, v)

	v, ok = params.GetInt("defaulted")
	assert.True(t, ok)
	assert.Equal(t, 10, v)

	_, ok = params.GetInt("bad")
	assert.False(t, ok)

	_, ok = params.GetInt("empty")
	assert.False(t, ok)

	_, ok = params.GetInt("nonexistent")
	assert.False(t, ok)
}

func TestParameters_GetBool(t *testing.T) {
	params := capability.Parameters{
		{Name: "verbose", Default: "false", Value: "true"},
		{Name: "defaulted", Default: "true"},
		{Name: "bad", Value: "not-a-bool"},
		{Name: "empty"},
	}

	v, ok := params.GetBool("verbose")
	assert.True(t, ok)
	assert.True(t, v)

	v, ok = params.GetBool("defaulted")
	assert.True(t, ok)
	assert.True(t, v)

	_, ok = params.GetBool("bad")
	assert.False(t, ok)

	_, ok = params.GetBool("empty")
	assert.False(t, ok)

	_, ok = params.GetBool("nonexistent")
	assert.False(t, ok)
}

func TestParameters_GetFloat(t *testing.T) {
	params := capability.Parameters{
		{Name: "rate", Default: "1.5", Value: "0.5"},
		{Name: "defaulted", Default: "2.5"},
		{Name: "integer", Value: "10"},
		{Name: "bad", Value: "not-a-number"},
		{Name: "empty"},
	}

	v, ok := params.GetFloat("rate")
	assert.True(t, ok)
	assert.Equal(t, 0.5, v)

	v, ok = params.GetFloat("defaulted")
	assert.True(t, ok)
	assert.Equal(t, 2.5, v)

	v, ok = params.GetFloat("integer")
	assert.True(t, ok)
	assert.Equal(t, 10.0, v)

	_, ok = params.GetFloat("bad")
	assert.False(t, ok)

	_, ok = params.GetFloat("empty")
	assert.False(t, ok)

	_, ok = params.GetFloat("nonexistent")
	assert.False(t, ok)
}

func TestParameters_Nil(t *testing.T) {
	var params capability.Parameters

	_, ok := params.GetString("anything")
	assert.False(t, ok)

	_, ok = params.GetInt("anything")
	assert.False(t, ok)

	_, ok = params.GetFloat("anything")
	assert.False(t, ok)

	_, ok = params.GetBool("anything")
	assert.False(t, ok)
}

func TestExecutionContext_Defaults(t *testing.T) {
	ctx := capability.ExecutionContext{}
	assert.False(t, ctx.Manual)
	assert.Nil(t, ctx.Parameters)
}

func TestEmitterFunc(t *testing.T) {
	called := false
	fn := capability.EmitterFunc(func(models ...any) error {
		called = true
		return nil
	})

	err := fn.Emit("a", "b")
	require.NoError(t, err)
	assert.True(t, called)
}

func TestEmitterFunc_Error(t *testing.T) {
	fn := capability.EmitterFunc(func(models ...any) error {
		return errors.New("emit failed")
	})

	err := fn.Emit("a")
	assert.EqualError(t, err, "emit failed")
}
