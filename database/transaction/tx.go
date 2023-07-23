package transaction

import "context"

type Tx interface {
	Transaction(context.Context, func(ctx context.Context) error) error
}
