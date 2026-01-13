package errors

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

// ErrorResponse is the standard shape your API returns on error
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`    // optional: machine-readable error code
	Details string `json:"details,omitempty"` // optional: extra info (avoid exposing internals!)
}

// MapAndSend maps application errors → HTTP status + sends JSON response
func MapAndSend(c echo.Context, err error) error {
	var (
		status int
		msg    string
		code   string
	)

	switch {
	// 400 Bad Request - client sent invalid data
	case errors.Is(err, ErrInvalidIdentityKey),
		errors.Is(err, ErrInvalidSignedPreKey),
		errors.Is(err, ErrInvalidSignedPreKeySignature),
		errors.Is(err, ErrInvalidOneTimePreKey),
		errors.Is(err, ErrInvalidUsername),
		errors.Is(err, ErrInvalidDisplayName):
		status = http.StatusBadRequest
		msg = "invalid input data"
		code = "INVALID_INPUT"

	// 409 Conflict - already exists
	case errors.Is(err, ErrUsernameTaken):
		status = http.StatusConflict
		msg = "username already taken"
		code = "USERNAME_TAKEN"

	// 401 Unauthorized - auth failed
	case errors.Is(err, ErrInvalidSignature),
		errors.Is(err, ErrInvalidSignature),
		errors.Is(err, ErrUnauthorized):
		status = http.StatusUnauthorized
		msg = "authentication failed"
		code = "AUTH_FAILED"

	// 404 Not Found
	case errors.Is(err, ErrUserNotFound):
		status = http.StatusNotFound
		msg = "user not found"
		code = "NOT_FOUND"

	// 429 Too Many Requests (rate limit, etc.)
	case errors.Is(err, ErrRateLimitExceeded):
		status = http.StatusTooManyRequests
		msg = "rate limit exceeded"
		code = "RATE_LIMIT"

	// 403 Forbidden (permission denied cases)
	case errors.Is(err, ErrForbidden):
		status = http.StatusForbidden
		msg = "forbidden"
		code = "FORBIDDEN"

	default:
		// Log the real error somewhere (sentry, zap, etc.)
		status = http.StatusInternalServerError
		msg = "internal server error"
		code = "INTERNAL_ERROR"
	}

	resp := ErrorResponse{
		Error: msg,
		Code:  code,
	}

	// Optional: add details only in development
	// if config.IsDev() {
	//     resp.Details = err.Error()
	// }

	return c.JSON(status, resp)
}
