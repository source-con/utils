package serverutils

import (
    "bufio"
    "bytes"
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/go-playground/assert/v2"
    "github.com/hashicorp/go-uuid"
)

func Test_LatencyLoggerMiddleware(t *testing.T) {
    os.Setenv("DEBUG", "true")

    rec := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "/health", nil)

    buf := &bytes.Buffer{}

    // Redirect STDOUT to a buffer
    stdout := os.Stdout
    r, w, err := os.Pipe()
    if err != nil {
        t.Errorf("failed to redirect STDOUT: %v", err)
    }

    go func() {
        scanner := bufio.NewScanner(r)
        for scanner.Scan() {
            buf.WriteString(scanner.Text())
        }
    }()

    os.Stdout = w

    svr := gin.New()

    svr.Use(LatencyLoggerMiddleware())

    svr.GET("/health", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    svr.ServeHTTP(rec, req)

    w.Close()
    os.Stdout = stdout

    t.Run("successfully printed latency log", func(t *testing.T) {
        out := buf.Bytes()
        assert.Equal(t, strings.Contains(string(out), "response latency"), true)
    })
}

func Test_RequestIDMiddleware(t *testing.T) {
    rec := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "/health", nil)

    svr := gin.New()
    svr.Use(RequestIDMiddleware())

    svr.GET("/health", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    svr.ServeHTTP(rec, req)

    t.Run("context has requestID", func(t *testing.T) {
        _, err := uuid.ParseUUID(rec.Header().Get("request-id"))
        assert.Equal(t, err, nil)
    })
}
