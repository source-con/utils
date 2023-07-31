package utils

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrGeneratingAccessToken = errors.New("error generating access token")
var ErrInvalidAccessToken = errors.New("invalid access token")

// GenerateAccessToken generates access token with signing method HS512 and given claims.
func GenerateAccessToken(ttl time.Duration, secret string, claims map[string]string) (string, error) {
	exp := time.Now().Add(ttl).Unix()

	jwtClaims := jwt.MapClaims{
		"exp": exp,
	}

	// iterate over claims and add them to jwt.MapClaims
	for key, value := range claims {
		jwtClaims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwtClaims)

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", ErrGeneratingAccessToken
	}

	return signedToken, nil
}

// GenerateRefreshToken generates refresh token from access token string
// it concatenates access token with current time and hashes it using sha512
func GenerateRefreshToken(accessToken string) string {
	// concatenate access token with current time
	key := accessToken + strconv.Itoa(int(time.Now().UnixMicro()))

	// hash the key
	h := sha512.New()
	h.Write([]byte(key))

	// return hex encoded hash
	hashString := hex.EncodeToString(h.Sum(nil))

	return hashString
}

// ParseToken parses the given token string using the given secret and returns the token object
func ParseToken(accessToken, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		return token, nil
	}

	return nil, ErrInvalidAccessToken
}
