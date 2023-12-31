package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/source-con/utils/database/transaction"
	"github.com/source-con/utils/types"
)

type PgTx struct {
	pgConn *gorm.DB
}

func (p PgTx) Transaction(ctx context.Context, f func(ctx context.Context) error) error {
	return p.pgConn.Transaction(func(tx *gorm.DB) error {
		return f(context.WithValue(ctx, types.TxCtxKey, tx))
	})
}

func NewTx(pgConn *gorm.DB) transaction.Tx {
	return &PgTx{pgConn: pgConn}
}
