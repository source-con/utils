package utils

import (
    "context"
    "crypto/rand"
    "io"
    "net/http"

    "github.com/jinzhu/copier"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"

    "github.com/source-con/utils/errors"
    "github.com/source-con/utils/logger"
)

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

// GenerateOTP generates a random OTP of given length
func GenerateOTP(length int) string {
    buffer := make([]byte, length)
    n, _ := io.ReadAtLeast(rand.Reader, buffer, length)

    if n != length {
        return ""
    }

    for i := 0; i < len(buffer); i++ {
        buffer[i] = table[int(buffer[i])%len(table)]
    }

    return string(buffer)
}

// CopyStruct copies the src struct to dest struct
func CopyStruct(dest interface{}, src interface{}, ignoreEmpty bool) error {
    err := copier.CopyWithOption(dest, src, copier.Option{IgnoreEmpty: ignoreEmpty})
    if err != nil {
        return errors.New(http.StatusInternalServerError, "failed to copy", errors.TAL, err, map[string]interface{}{"src": src, "dest": dest})
    }

    return nil
}

// GetPGDBFromCtx returns the pg db from context
// it is used to get the transaction object from context if present
func GetPGDBFromCtx(ctx context.Context, db *gorm.DB) *gorm.DB {
    if ctx == nil {
        return db
    }

    if val := ctx.Value(TxCtxKey); val != nil {
        if tx, ok := val.(*gorm.DB); ok {
            return tx
        }
    }

    return db
}

// GeneratePasswordHash generates the bcrypt hash
func GeneratePasswordHash(password string) ([]byte, error) {
    log := logger.GetInstance()

    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        log.Error(context.Background(), err, "failed to generate password hash", nil)

        return nil, errors.New(http.StatusInternalServerError, "failed to generate password hash", errors.TAL, err, nil)
    }

    return hash, nil
}
