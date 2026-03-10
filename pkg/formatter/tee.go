package formatter

import (
	"context"
	"errors"
)

// TeeFormatter writes findings to multiple formatters simultaneously.
// Useful for outputting to terminal and file at the same time.
type TeeFormatter struct {
	formatters []Formatter
}

// NewTee creates a formatter that writes to all provided formatters.
// At least one formatter must be provided.
func NewTee(formatters ...Formatter) (*TeeFormatter, error) {
	if len(formatters) == 0 {
		return nil, errors.New("at least one formatter required")
	}
	return &TeeFormatter{formatters: formatters}, nil
}

func (t *TeeFormatter) Initialize(ctx context.Context, info ToolInfo) error {
	var errs []error
	for _, f := range t.formatters {
		if err := f.Initialize(ctx, info); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *TeeFormatter) Format(ctx context.Context, finding Finding) error {
	var errs []error
	for _, f := range t.formatters {
		if err := f.Format(ctx, finding); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *TeeFormatter) Complete(ctx context.Context, summary Summary) error {
	var errs []error
	for _, f := range t.formatters {
		if err := f.Complete(ctx, summary); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *TeeFormatter) Close() error {
	var errs []error
	for _, f := range t.formatters {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
