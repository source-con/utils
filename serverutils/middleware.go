package serverutils

import (
	"bytes"
	"context"
	"crypto/sha512"
	"net/http"
	"os"
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
	"github.com/source-con/utils/types"
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
			"requestID": c.GetString(string(types.RequestIDCtxKey)),
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
		c.Set(string(types.RequestIDCtxKey), requestID)

		c.Next()
	}
}

// AuthMiddleware is a Gin middleware to authenticate the user using JWT
func AuthMiddleware(secret string, claimKeys ...types.Claim) gin.HandlerFunc {
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
			if _, ok = mapClaims[string(claim)]; ok {
				c.Set(string(claim), mapClaims[string(claim)])
			}
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

		// if the response is already written internally by gin, return
		if c.Writer.Written() {
			return
		}

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

func BindingError(c *gin.Context, err error) {
	c.AbortWithStatusJSON(c.Writer.Status(), errors.HTTPError{
		Code:       c.Writer.Status(),
		Message:    "invalid request body",
		Err:        err.Error(),
		Resolution: "please check request body and try again",
		Meta:       nil,
	})
}

func BasicAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, password, _ := c.Request.BasicAuth()

		hashedUsername := sha512.Sum512([]byte(username))
		hashedPassword := sha512.Sum512([]byte(password))

		expectedUsername := sha512.Sum512([]byte(os.Getenv("AUTH_USERNAME")))
		expectedPassword := sha512.Sum512([]byte(os.Getenv("AUTH_PASSWORD")))

		u := bytes.Compare(hashedUsername[:], expectedUsername[:])
		p := bytes.Compare(hashedPassword[:], expectedPassword[:])

		if u == 0 && p == 0 {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, errors.HTTPError{
			Code:       http.StatusUnauthorized,
			Message:    "unauthorized",
			Err:        "unauthorized",
			Resolution: "check username and password and try again",
			Meta:       nil,
		})
	}
}

func MetaInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		meta := types.Meta{
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Role:      c.GetString("role"),
			ID:        c.GetString("id"),
		}

		c.Set("meta", meta)
		c.Next()
	}
}
