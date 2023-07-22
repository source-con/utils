package utils

import (
    "context"
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    jwtv5 "github.com/golang-jwt/jwt/v5"
    "github.com/hashicorp/go-uuid"
)

type ContextKey string

const (
    RequestIDCtxKey ContextKey = "requestID"
    UserRoleCtxKey  ContextKey = "role"
    UserIDCtxKey    ContextKey = "userID"
)

// LatencyLoggerMiddleware is Gin middleware which logs the latency of the request
func LatencyLoggerMiddleware() gin.HandlerFunc {
    log := GetInstance()

    return func(c *gin.Context) {
        start := time.Now()

        c.Next()

        latency := time.Since(start)

        log.Debug(context.Background(), "response latency", map[string]interface{}{
            "latency":   latency,
            "requestID": c.GetString(string(RequestIDCtxKey)),
            "method":    c.Request.Method,
            "path":      c.Request.URL.Path,
        })
    }
}

// RequestIDMiddleware is Gin middleware which generates a requestID and sets it in the context
func RequestIDMiddleware() gin.HandlerFunc {
    log := GetInstance()

    return func(c *gin.Context) {
        requestID, err := uuid.GenerateUUID()
        if err != nil {
            log.Error(context.Background(), err, "failed to generate requestID", nil)
        }

        c.Header("request-id", requestID)
        c.Set(string(RequestIDCtxKey), requestID)

        c.Next()
    }
}

var authMiddlewareCaller = "authMiddleware"

// AuthMiddleware is a Gin middleware to authenticate the user using JWT
func AuthMiddleware(secret string, claimKeys ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // get accessToken from context
        accessToken := c.GetHeader("Authorization")
        if accessToken == "" {
            c.AbortWithStatusJSON(
                http.StatusUnauthorized,
                HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    "empty access token",
                    Err:        "empty access token provided",
                    Caller:     authMiddlewareCaller,
                    Resolution: "login again / provide access token",
                    Meta:       nil,
                },
            )

            return
        }

        // split accessToken in 2 parts and check if first part is "Bearer"
        parts := strings.Split(accessToken, " ")
        if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
            c.AbortWithStatusJSON(
                http.StatusUnauthorized,
                HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    "invalid access token",
                    Err:        "invalid access token provided",
                    Caller:     authMiddlewareCaller,
                    Resolution: "login again / provide valid access token",
                    Meta:       nil,
                })

            return
        }

        tokenString := parts[1]

        // parse token
        token, err := ParseToken(tokenString, secret)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized,
                HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    "invalid access token",
                    Err:        err.Error(),
                    Caller:     authMiddlewareCaller,
                    Resolution: "login again / provide valid access token",
                    Meta:       nil,
                })

            return
        }

        mapClaims, ok := token.Claims.(jwtv5.MapClaims)
        if !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized,
                HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    ISE,
                    Err:        "failed to parse claimKeys",
                    Caller:     authMiddlewareCaller,
                    Resolution: TAL,
                    Meta:       nil,
                })

            return
        }

        userRole := mapClaims["role"]
        if userRole == nil || userRole == "unknown" {
            c.AbortWithStatusJSON(http.StatusForbidden, HTTPError{
                Code:       http.StatusForbidden,
                Message:    "access forbidden: unknown user role",
                Err:        "unknown user role",
                Caller:     authMiddlewareCaller,
                Resolution: "login again",
                Meta:       nil,
            })

            return
        }

        for _, claim := range claimKeys {
            c.Set(claim, mapClaims[claim])
        }

        c.Next()
    }
}
