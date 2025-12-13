package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gossip/config"
)

type Logger struct {
	logger *zap.SugaredLogger
	config *config.Config
}

// New creates a new Zap SugaredLogger based on the provided configuration.
func NewLogger(cfg *config.Config) (*Logger, error) {
	var zapCfg zap.Config

	switch {
	case cfg.LoggerMode.Development:
		// Development mode: human-readable output, debug level, stack traces
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // Colored output for console
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case cfg.LoggerMode.Prod:
		// Production mode: JSON output, info level, no stack traces by default
		zapCfg = zap.NewProductionConfig()
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	default:
		zapCfg = zap.NewDevelopmentConfig()
		zapCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // Colored output for console
		zapCfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)

	}

	// Build the logger
	logger, err := zapCfg.Build()
	if err != nil {
		return nil, err
	}

	// Return the SugaredLogger
	l := newLoggerStruct(logger.Sugar())
	return l, nil
}

func newLoggerStruct(logger *zap.SugaredLogger) *Logger {
	return &Logger{
		logger: logger,
	}
}

// --- Logging methods ---

func (l *Logger) Debug(args ...any) {
	l.logger.Debug(args...)
}

func (l *Logger) Info(args ...any) {
	l.logger.Info(args...)
}

func (l *Logger) Warn(args ...any) {
	l.logger.Warn(args...)
}

func (l *Logger) Error(args ...any) {
	l.logger.Error(args...)
}

func (l *Logger) Fatal(args ...any) {
	l.logger.Fatal(args...)
}

func (l *Logger) Panic(args ...any) {
	l.logger.Panic(args...)
}

// --- Formatted versions (like printf) ---

func (l *Logger) Debugf(template string, args ...any) {
	l.logger.Debugf(template, args...)
}

func (l *Logger) Infof(template string, args ...any) {
	l.logger.Infof(template, args...)
}

func (l *Logger) Warnf(template string, args ...any) {
	l.logger.Warnf(template, args...)
}

func (l *Logger) Errorf(template string, args ...any) {
	l.logger.Errorf(template, args...)
}

func (l *Logger) Fatalf(template string, args ...any) {
	l.logger.Fatalf(template, args...)
}

func (l *Logger) Panicf(template string, args ...any) {
	l.logger.Panicf(template, args...)
}

// Sync flushes any buffered log entries.
func (l *Logger) Sync() error {
	return l.logger.Sync()
}
