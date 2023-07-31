package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAccessToken(t *testing.T) {
	// define test case values
	ttl := 2 * time.Minute
	secret := "secret"
	claims := map[string]string{"username": "testuser"}

	// call the function
	tokenString, err := GenerateAccessToken(ttl, secret, claims)
	if err != nil {
		t.Fatal(err)
	}

	// assertions
	assert.Nil(t, err)
	assert.NotEmpty(t, tokenString)

	// verifying the token
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, jwt.SigningMethodHS512, token.Method)
		return []byte(secret), nil
	})
	assert.Nil(t, err)
	assert.True(t, parsedToken.Valid)

	// verify the claims
	assert.Equal(t, claims["username"], parsedToken.Claims.(jwt.MapClaims)["username"])
}
