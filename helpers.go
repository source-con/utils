package utils

import (
    "crypto/rand"
    "io"
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
