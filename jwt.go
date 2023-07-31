package utils

import (
	"errors"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

var ErrGeneratingAccessToken = errors.New("error generating access token")
var ErrGeneratingARefreshToken = errors.New("error generating refresh token")
var ErrInvalidAccessToken = errors.New("invalid access token")

// GenerateAccessToken generates access token with signing method HS512 and given claims.
func GenerateAccessToken(ttl time.Duration, secret string, claims map[string]string) (string, error) {
	exp := time.Now().Add(ttl).Unix()

	jwtClaims := jwtv5.MapClaims{
		"exp": exp,
	}

	// iterate over claims and add them to jwt.MapClaims
	for key, value := range claims {
		jwtClaims[key] = value
	}

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS512, jwtClaims)

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", ErrGeneratingAccessToken
	}

	return signedToken, nil
}

// GenerateRefreshToken generates refresh token from access token string
// it concatenates access token with current time and hashes it using sha512
func GenerateRefreshToken(accessToken, secret string) (string, error) {
	token, err := ParseToken(accessToken, secret)
	if err != nil {
		return "", ErrInvalidAccessToken
	}

	jwtv5.NewWithClaims(jwtv5.SigningMethodHS512, token.Claims)

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", ErrGeneratingARefreshToken
	}

	return signedToken, nil
}

// ParseToken parses the given token string using the given secret and returns the token object
func ParseToken(accessToken, secret string) (*jwtv5.Token, error) {
	token, err := jwtv5.Parse(accessToken, func(token *jwtv5.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtv5.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if token.Valid {
		return token, nil
	}

	return nil, ErrInvalidAccessToken
}
