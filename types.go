package utils

type ContextKey string

const (
    RequestIDCtxKey ContextKey = "requestID"
    TxCtxKey        ContextKey = "tx"
)
