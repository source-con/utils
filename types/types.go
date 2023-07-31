package types

type ContextKey string

const (
	RequestIDCtxKey ContextKey = "requestID"
	TxCtxKey        ContextKey = "tx"
)

type Meta struct {
	IP        string `json:"ip"`
	UserAgent string `json:"userAgent"`
	Role      string `json:"role"`
	ID        string `json:"id"`
}

type Claim string
