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

func TestGenerateRefreshToken(t *testing.T) {
	// define test case values
	ttl := 2 * time.Minute
	secret := "secret"
	claims := map[string]string{"username": "testuser"}

	// call the function
	tokenString, err := GenerateAccessToken(ttl, secret, claims)
	if err != nil {
		t.Fatal(err)
	}

	token, err := GenerateRefreshToken(tokenString, secret)

	// Test case: Check if a token is returned with no error
	t.Run("token creation success", func(t *testing.T) {
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	// Test case: Check if error is returned when invalid access token is passed
	t.Run("invalid access token", func(t *testing.T) {
		_, err = GenerateRefreshToken("invalidToken", secret)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidAccessToken, err)
	})

	// Test case: Check if error is returned when invalid secret is passed
	t.Run("invalid secret", func(t *testing.T) {
		_, err = GenerateRefreshToken(tokenString, "invalidSecret")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidAccessToken, err)
	})
}
