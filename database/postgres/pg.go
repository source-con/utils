package postgres

import (
    "context"
    "time"

    "github.com/pkg/errors"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/plugin/dbresolver"

    "github.com/source-con/utils/logger"
)

type Config struct {
    URL             string
    ReplicaURL      string
    Debug           bool
    MaxIdleConns    int
    IdleConnTimeout int
    MaxOpenConns    int
    ConnMaxLifetime int
}

// GetConnection returns a new postgres connection
func GetConnection(cfg *Config) (*gorm.DB, error) {
    log := logger.GetLoggerInstance()
    pgLogger := logger.InitPGLogger()

    pgDB, err := gorm.Open(postgres.New(
        postgres.Config{
            DSN: cfg.URL,
        },
    ), &gorm.Config{
        Logger:      pgLogger,
        PrepareStmt: true,
    })
    if err != nil {
        log.Error(context.Background(), err, "failed to connect to postgres", nil)

        return nil, errors.Wrap(err, "failed to connect to postgres")
    }

    if cfg.Debug {
        pgDB = pgDB.Debug()
    }

    sqlDB, err := pgDB.DB()
    if err != nil {
        log.Error(context.Background(), err, "failed to get sqlDB", nil)

        return nil, errors.Wrap(err, "failed to get sqlDB")
    }

    // connection pool
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
    sqlDB.SetConnMaxIdleTime(time.Second * time.Duration(cfg.IdleConnTimeout))
    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetConnMaxLifetime(time.Second * time.Duration(cfg.ConnMaxLifetime))

    if cfg.ReplicaURL != "" {
        err = setupReplicaDB(pgDB, cfg, log, pgLogger)
        if err != nil {
            log.Error(context.Background(), err, "failed to setup replica db", nil)

            return nil, errors.Wrap(err, "failed to setup replica db")
        }
    }

    return pgDB, nil
}

func setupReplicaDB(db *gorm.DB, cfg *Config, logger logger.Logger, pgLogger logger.PGLogger) error {
    replicaDB, err := gorm.Open(postgres.New(
        postgres.Config{
            DSN: cfg.ReplicaURL,
        },
    ), &gorm.Config{
        Logger:      pgLogger,
        PrepareStmt: true,
    })
    if err != nil {
        logger.Error(context.Background(), err, "failed to connect to replica postgres", map[string]interface{}{"url": cfg.URL})

        return errors.Wrap(err, "failed to connect to postgres")
    }

    if cfg.Debug {
        replicaDB = replicaDB.Debug()
    }

    sqlDB, err := replicaDB.DB()
    if err != nil {
        return errors.Wrap(err, "failed to get sqlDB")
    }

    // connection pool
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
    sqlDB.SetConnMaxIdleTime(time.Second * time.Duration(cfg.IdleConnTimeout))
    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetConnMaxLifetime(time.Second * time.Duration(cfg.ConnMaxLifetime))

    err = db.Use(dbresolver.Register(dbresolver.Config{
        Replicas: []gorm.Dialector{
            postgres.New(postgres.Config{Conn: sqlDB}),
        },
        // sources/replicas load balancing policy
        Policy:            dbresolver.RandomPolicy{}, // does not really matter as there is only single replica right now
        TraceResolverMode: true,
    }))
    if err != nil {
        return errors.Wrap(err, "failed to register replica")
    }

    return nil
}

type BaseModel struct {
    CreatedAt time.Time      `json:"created_at"`
    UpdatedAt time.Time      `json:"updated_at"`
    DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}
