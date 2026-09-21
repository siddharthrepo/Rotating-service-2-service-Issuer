package telemetry

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func newEncoder(format string) zapcore.Encoder {
	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = "ts"
	cfg.MessageKey = "msg"
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeDuration = zapcore.MillisDurationEncoder

	if format == "text" {
		cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		return zapcore.NewConsoleEncoder(cfg)
	}
	cfg.EncodeLevel = zapcore.LowercaseLevelEncoder
	return zapcore.NewJSONEncoder(cfg)
}
