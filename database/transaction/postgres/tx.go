package postgres

import (
    "context"

    "gorm.io/gorm"

    "github.com/source-con/utils"
    "github.com/source-con/utils/database/transaction"
)

type PgTx struct {
    pgConn *gorm.DB
}

func (p PgTx) Transaction(ctx context.Context, f func(ctx context.Context) error) error {
    return p.pgConn.Transaction(func(tx *gorm.DB) error {
        ctx = context.WithValue(ctx, utils.TxCtxKey, tx)

        return f(ctx)
    })
}

func NewTx(pgConn *gorm.DB) transaction.Tx {
    return &PgTx{pgConn: pgConn}
}
