// pkg/httperrors/errors.go
package httperrors

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	appErrors "gossip/pkg/errors" // ← your domain errors package
)

type ErrorResponse struct {
	Error   string `json:"error"`             // human-readable message
	Code    string `json:"code,omitempty"`    // machine-readable error code
	Status  int    `json:"status"`            // HTTP status code (for clients that need it)
	Details string `json:"details,omitempty"` // only in dev / debug mode
}

// Send maps domain errors → HTTP response + sends JSON
func Send(c echo.Context, err error) error {
	if err == nil {
		return nil // nothing to do
	}

	status := http.StatusInternalServerError
	code := "INTERNAL_ERROR"
	message := "internal server error"

	switch {
	// === 400 Bad Request ===
	case errors.Is(err, appErrors.ErrInvalidUsername),
		errors.Is(err, appErrors.ErrInvalidDisplayName),
		errors.Is(err, appErrors.ErrInvalidChallengeID),
		errors.Is(err, appErrors.ErrInvalidSignedPreKey),
		errors.Is(err, appErrors.ErrInvalidOneTimePreKey),
		errors.Is(err, appErrors.ErrInvalidSignedPreKeySignature),
		errors.Is(err, appErrors.ErrInvalidUserID),
		errors.Is(err, appErrors.ErrInvalidIdentityKey),
		errors.Is(err, appErrors.ErrInvalidEncryptionKey),
		errors.Is(err, appErrors.ErrInvalidQuery),
		errors.Is(err, appErrors.ErrChallengeNotFound),
		errors.Is(err, appErrors.ErrChallengeExpired),
		errors.Is(err, appErrors.ErrChallengeUsed),
		errors.Is(err, appErrors.ErrInvalidChallenge):
		status = http.StatusBadRequest
		code = "INVALID_INPUT"
		message = err.Error() // usually already good messages

	// === 401 Unauthorized ===
	case errors.Is(err, appErrors.ErrInvalidSignature):
		status = http.StatusUnauthorized
		code = "AUTHENTICATION_FAILED"
		message = "authentication failed"

	// === 403 Forbidden ===
	case errors.Is(err, appErrors.ErrForbidden):
		status = http.StatusForbidden
		code = "FORBIDDEN"
		message = "forbidden"

	// === 404 Not Found ===
	case errors.Is(err, appErrors.ErrUserNotFound),
		errors.Is(err, appErrors.ErrUserOrBundleNotFound):
		status = http.StatusNotFound
		code = "NOT_FOUND"
		message = err.Error()

	// === 409 Conflict ===
	case errors.Is(err, appErrors.ErrUsernameTaken):
		status = http.StatusConflict
		code = "ALREADY_EXISTS"
		message = "username already taken"

	// === 429 Too Many Requests ===
	case errors.Is(err, appErrors.ErrRateLimitExceeded):
		status = http.StatusTooManyRequests
		code = "RATE_LIMIT_EXCEEDED"
		message = "rate limit exceeded"

	// === 428 Precondition Required / 412 Precondition Failed ===
	case errors.Is(err, appErrors.ErrIdentityKeyMissing),
		errors.Is(err, appErrors.ErrSignedPreKeyMissing),
		errors.Is(err, appErrors.ErrNoPreKeysAvailable):
		status = http.StatusPreconditionRequired // or 412
		code = "PRECONDITION_REQUIRED"
		message = err.Error()

	default:
		// Log original error somewhere (zap, sentry, etc.)
		// c.Logger().Error("unhandled error", zap.Error(err))
	}

	resp := ErrorResponse{
		Error:  message,
		Code:   code,
		Status: status,
	}
	return c.JSON(status, resp)
}
