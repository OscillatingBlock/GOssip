package errors

import "fmt"

type AppError struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Cause   error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *AppError) Unwrap() error { return e.Cause }

// Constructors
func New(code Code, message string) error {
	return &AppError{Code: code, Message: message}
}

func Wrap(code Code, message string, cause error) error {
	return &AppError{Code: code, Message: message, Cause: cause}
}

func InvalidArg(msg string) error {
	return New(CodeInvalidArgument, msg)
}

func NotFound(msg string) error {
	return New(CodeNotFound, msg)
}

func AlreadyExists(msg string) error {
	return New(CodeAlreadyExists, msg)
}

func Unauthorized(msg string) error {
	return New(CodeUnauthenticated, msg)
}

func Forbidden(msg string) error {
	return New(CodePermissionDenied, msg)
}

func Internal(msg string) error {
	return New(CodeInternal, msg)
}

func FailedPrecondition(msg string) error {
	return New(CodeFailedPrecondition, msg)
}
