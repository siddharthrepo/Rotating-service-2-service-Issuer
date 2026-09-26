// Package telemetry wires structured logging.
package telemetry

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

// NewLogger builds the application logger.
func NewLogger(cfg structs.Log) (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	enc := newEncoder(cfg.Format)
	out := zapcore.Lock(os.Stdout)

	routine := zap.LevelEnablerFunc(func(l zapcore.Level) bool {
		return l >= level && l < zapcore.WarnLevel
	})

	important := zap.LevelEnablerFunc(func(l zapcore.Level) bool {
		return l >= zapcore.WarnLevel
	})

	routineCore := zapcore.NewCore(enc, out, routine)
	if cfg.SampleInitial > 0 {

		routineCore = zapcore.NewSamplerWithOptions(
			routineCore, time.Second, cfg.SampleInitial, cfg.SampleThereafter)
	}

	core := zapcore.NewTee(routineCore, zapcore.NewCore(enc, out, important))

	return zap.New(core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	), nil
}

// Sync flushes buffered entries.
func Sync(log *zap.Logger) {
	_ = log.Sync()
}
