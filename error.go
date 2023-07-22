package utils

const ISE = "internal server error"
const SWR = "something went wrong"
const TAL = "try again later"

// AppError represents an application error
type AppError struct {
    Code       int
    Message    string
    Err        error
    Caller     string
    Resolution string
    Meta       interface{}
}

// HTTPError represents error as http response for AppError
type HTTPError struct {
    Code       int         `json:"code"`
    Message    string      `json:"message"`
    Err        string      `json:"error"`
    Caller     string      `json:"caller"`
    Resolution string      `json:"resolution,omitempty"`
    Meta       interface{} `json:"meta,omitempty"`
}

func (e AppError) Error() string {
    return e.Err.Error()
}

func (e AppError) As(err any) bool {
    if err == nil {
        return false
    }

    if err, ok := err.(*AppError); ok {
        *err = e
        return true
    }

    return false
}

// New creates a new AppError.
func New(code int, caller string, msg string, resolution string, err error, meta interface{}) *AppError {
    return &AppError{
        Code:       code,
        Caller:     caller,
        Message:    msg,
        Resolution: resolution,
        Meta:       meta,
        Err:        err,
    }
}
