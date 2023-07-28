package serverutils

import (
    "context"
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/go-playground/validator/v10"
    jwtv5 "github.com/golang-jwt/jwt/v5"
    "github.com/hashicorp/go-uuid"
    pkgerr "github.com/pkg/errors"

    "github.com/source-con/utils"
    "github.com/source-con/utils/errors"
    "github.com/source-con/utils/logger"
)

// LatencyLoggerMiddleware is Gin middleware which logs the latency of the request
func LatencyLoggerMiddleware() gin.HandlerFunc {
    log := logger.GetInstance()

    return func(c *gin.Context) {
        start := time.Now()

        c.Next()

        latency := time.Since(start)

        log.Debug(context.Background(), "response latency", map[string]interface{}{
            "latency":   latency,
            "requestID": c.GetString(string(utils.RequestIDCtxKey)),
            "method":    c.Request.Method,
            "path":      c.Request.URL.Path,
        })
    }
}

// RequestIDMiddleware is Gin middleware which generates a requestID and sets it in the context
func RequestIDMiddleware() gin.HandlerFunc {
    log := logger.GetInstance()

    return func(c *gin.Context) {
        requestID, err := uuid.GenerateUUID()
        if err != nil {
            log.Error(context.Background(), err, "failed to generate requestID", nil)
        }

        c.Header("request-id", requestID)
        c.Set(string(utils.RequestIDCtxKey), requestID)

        c.Next()
    }
}

// AuthMiddleware is a Gin middleware to authenticate the user using JWT
func AuthMiddleware(secret string, claimKeys ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // get accessToken from context
        accessToken := c.GetHeader("Authorization")
        if accessToken == "" {
            c.AbortWithStatusJSON(
                http.StatusUnauthorized,
                errors.HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    "empty access token",
                    Err:        "empty access token provided",
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
                errors.HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    "invalid access token",
                    Err:        "invalid access token provided",
                    Resolution: "login again / provide valid access token",
                    Meta:       nil,
                })

            return
        }

        tokenString := parts[1]

        // parse token
        token, err := utils.ParseToken(tokenString, secret)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized,
                errors.HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    "invalid access token",
                    Err:        err.Error(),
                    Resolution: "login again / provide valid access token",
                    Meta:       nil,
                })

            return
        }

        mapClaims, ok := token.Claims.(jwtv5.MapClaims)
        if !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized,
                errors.HTTPError{
                    Code:       http.StatusUnauthorized,
                    Message:    errors.ISE,
                    Err:        "failed to parse claimKeys",
                    Resolution: errors.TAL,
                    Meta:       nil,
                })

            return
        }

        userRole := mapClaims["role"]
        if userRole == nil || userRole == "unknown" {
            c.AbortWithStatusJSON(http.StatusForbidden, errors.HTTPError{
                Code:       http.StatusForbidden,
                Message:    "access forbidden: unknown user role",
                Err:        "unknown user role",
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

func ErrorMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
        c.Next()

        httpError := new(errors.HTTPError)
        httpError.Code = http.StatusInternalServerError
        httpError.Message = "Internal Server Error"
        httpError.Resolution = "Please try again later"
        httpError.Meta = nil
        errs := c.Errors

        if len(errs) > 0 {
            err := errs[0].Err
            httpError.Err = err.Error()

            appErr := new(errors.AppError)
            validationErr := new(validator.ValidationErrors)
            ginErr := new(gin.Error)

            switch {
            case pkgerr.As(err, validationErr):
                httpError.Message = validationErr.Error()
                httpError.Code = http.StatusBadRequest
                httpError.Message = "Bad Request"
                httpError.Resolution = "Provide valid data and try again!"
                c.JSON(httpError.Code, httpError)
            case pkgerr.As(err, ginErr):
                httpError.Message = ginErr.Error()
                httpError.Meta = ginErr.Meta
                c.JSON(httpError.Code, httpError)
            case pkgerr.As(err, appErr):
                httpError.Code = appErr.Code
                httpError.Resolution = appErr.Resolution
                httpError.Message = appErr.Message
                httpError.Err = appErr.Err.Error()

                c.JSON(httpError.Code, httpError)
            default:
                c.JSON(http.StatusInternalServerError, httpError)
            }
        }
    }
}