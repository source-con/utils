package utils

import (
    "context"
    "os"
    "sync"
    "time"

    "github.com/rs/zerolog"

    gormLogger "gorm.io/gorm/logger"
)

// Logger is the interface for the logger.
type Logger interface {
    Info(ctx context.Context, msg string, fields map[string]interface{})
    Debug(ctx context.Context, msg string, fields map[string]interface{})
    Error(ctx context.Context, err error, msg string, fields map[string]interface{})
}

type PGLogger interface {
    LogMode(gormLogger.LogLevel) gormLogger.Interface
    Info(context.Context, string, ...interface{})
    Warn(context.Context, string, ...interface{})
    Error(context.Context, string, ...interface{})
    Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error)
}

// logger is the implementation struct of the Logger interface.
type logger struct {
    logger zerolog.Logger
}

type pgLogger struct {
    logger   zerolog.Logger
    logLevel gormLogger.LogLevel
}

var once sync.Once
var log Logger

// GetInstance initializes the logger.
func GetInstance() Logger {
    once.Do(func() {
        initLogger()
    })

    return log
}

func initLogger() {
    debug := os.Getenv("DEBUG") == "true"

    zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

    l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: false, TimeFormat: time.RFC3339})

    if debug {
        l = l.Level(zerolog.DebugLevel)
    } else {
        l = l.Level(zerolog.InfoLevel)
    }

    l = l.
        With().
        Timestamp().
        CallerWithSkipFrameCount(3).
        Logger()

    log = &logger{logger: l}
}

func InitPGLogger() PGLogger {
    zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

    l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: false, TimeFormat: time.RFC3339})

    l = l.
        With().
        Timestamp().
        CallerWithSkipFrameCount(3).
        Logger()

    return &pgLogger{logger: l}
}

// Info logs the info level logs.
func (l logger) Info(ctx context.Context, msg string, fields map[string]interface{}) {
    fields = addRequestIDToFields(ctx, fields)

    l.logger.Info().Fields(fields).Msg(msg)
}

// Debug logs the debug level logs.
func (l logger) Debug(ctx context.Context, msg string, fields map[string]interface{}) {
    fields = addRequestIDToFields(ctx, fields)

    l.logger.Debug().Fields(fields).Msg(msg)
}

// Error logs the error level logs.
func (l logger) Error(ctx context.Context, err error, msg string, fields map[string]interface{}) {
    fields = addRequestIDToFields(ctx, fields)

    output := l.logger.Output(os.Stderr)
    output.Error().Fields(fields).Err(err).Msg(msg)
}

func addRequestIDToFields(ctx context.Context, fields map[string]interface{}) map[string]interface{} {
    if fields == nil {
        fields = make(map[string]interface{})
    }

    if ctx == nil {
        return fields
    }

    if val := ctx.Value(RequestIDCtxKey); val != nil {
        if requestID, ok := val.(string); ok {
            fields[string(RequestIDCtxKey)] = requestID
        }
    }

    return fields
}

func (p *pgLogger) LogMode(level gormLogger.LogLevel) gormLogger.Interface {
    log := *p
    log.logLevel = level

    return &log
}

func (p pgLogger) Info(ctx context.Context, s string, i ...interface{}) {
    if p.logLevel >= gormLogger.Info {
        p.logger.Info().Fields(i).Msg(s)
    }
}

func (p pgLogger) Warn(ctx context.Context, s string, i ...interface{}) {
    if p.logLevel >= gormLogger.Warn {
        p.logger.Warn().Fields(i).Msg(s)
    }
}

func (p pgLogger) Error(ctx context.Context, s string, i ...interface{}) {
    if p.logLevel >= gormLogger.Error {
        p.logger.Error().Fields(i).Msg(s)
    }
}

func (p pgLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
    if p.logLevel > gormLogger.Silent {
        elapsed := time.Since(begin)
        switch {
        case err != nil && p.logLevel >= gormLogger.Error:
            sql, rows := fc()
            p.logger.Error().Fields(map[string]interface{}{
                "rows": rows,
                "sql":  sql,
            }).Err(err).Msg("trace")
        case elapsed > time.Second && p.logLevel >= gormLogger.Warn:
            sql, rows := fc()
            p.logger.Warn().Fields(map[string]interface{}{
                "rows": rows,
                "sql":  sql,
            }).Msg("trace")
        case p.logLevel >= gormLogger.Info:
            sql, rows := fc()
            p.logger.Info().Fields(map[string]interface{}{
                "rows": rows,
                "sql":  sql,
            }).Msg("trace")
        }
    }
}
