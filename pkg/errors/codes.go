package errors

type Code string

const (
	CodeUnknown            Code = "UNKNOWN"
	CodeInvalidArgument    Code = "INVALID_ARGUMENT"
	CodeNotFound           Code = "NOT_FOUND"
	CodeAlreadyExists      Code = "ALREADY_EXISTS"
	CodePermissionDenied   Code = "PERMISSION_DENIED"
	CodeUnauthenticated    Code = "UNAUTHENTICATED"
	CodeFailedPrecondition Code = "FAILED_PRECONDITION"
	CodeInternal           Code = "INTERNAL"
	CodeDeadlineExceeded   Code = "DEADLINE_EXCEEDED"
)
